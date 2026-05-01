package parser

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ParseAuthLog parses auth.log, all rotated files (.0–.6), and the security file,
// returning all entries chronologically sorted.
func ParseAuthLog(dir string) ([]models.AuthLogEntry, error) {
	logDir := resolveLogDir(dir)

	var allEntries []models.AuthLogEntry

	// Parse rotated auth logs oldest first (.6 → .0)
	for i := 6; i >= 0; i-- {
		src := fmt.Sprintf("auth.%d", i)
		path := filepath.Join(logDir, fmt.Sprintf("auth.log.%d", i))
		if entries, err := parseAuthLogFile(path, src); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	// Parse current auth.log
	if entries, err := parseAuthLogFile(filepath.Join(logDir, "auth.log"), "auth"); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Parse security rotations (bzip2-compressed: security.0.bz2, security.1.bz2, …)
	for i := 9; i >= 0; i-- {
		src := fmt.Sprintf("security.%d", i)
		bzPath := filepath.Join(logDir, fmt.Sprintf("security.%d.bz2", i))
		if f, err := os.Open(bzPath); err == nil {
			entries, _ := parseSecurityLogReader(bzip2.NewReader(f), src)
			allEntries = append(allEntries, entries...)
			f.Close()
		} else {
			// Also try plain (no compression)
			plainPath := filepath.Join(logDir, fmt.Sprintf("security.%d", i))
			if entries, err := parseSecurityLogFile(plainPath, src); err == nil {
				allEntries = append(allEntries, entries...)
			}
		}
	}
	if entries, err := parseSecurityLogFile(filepath.Join(logDir, "security"), "security"); err == nil {
		allEntries = append(allEntries, entries...)
	}

	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	return allEntries, nil
}

func parseAuthLogFile(path, source string) ([]models.AuthLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.AuthLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseAuthLogLine(line)
		if err != nil {
			continue
		}
		entry.Source = source
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseSecurityLogFile(path, source string) ([]models.AuthLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseSecurityLogReader(file, source)
}

// parseSecurityLogReader parses BSD security log lines from any io.Reader.
// Format: 2026-04-14T03:12:31.771968+00:00 HOSTNAME process[PID] message
func parseSecurityLogReader(r io.Reader, source string) ([]models.AuthLogEntry, error) {
	tsRegex  := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*[+-]\d{2}:\d{2})\s+(\S+)\s+(\S+?)\[(\d+)\]\s+(.*)`)
	tsRegex2 := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*[+-]\d{2}:\d{2})\s+(\S+)\s+(.*)`)

	var entries []models.AuthLogEntry
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entry := models.AuthLogEntry{
			RawLine: line,
			Level:   "INFO",
			Source:  source,
		}
		if m := tsRegex.FindStringSubmatch(line); m != nil {
			if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
				entry.Timestamp = t
			}
			entry.Hostname = m[2]
			entry.Process  = m[3]
			entry.PID      = m[4]
			entry.Message  = m[5]
		} else if m := tsRegex2.FindStringSubmatch(line); m != nil {
			if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
				entry.Timestamp = t
			}
			entry.Hostname = m[2]
			entry.Message  = m[3]
		} else {
			entry.Message = line
		}
		entry = classifySecurityEvent(entry)
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// classifySecurityEvent assigns EventType and Level based on message content.
func classifySecurityEvent(e models.AuthLogEntry) models.AuthLogEntry {
	msg := e.Message
	proc := e.Process
	switch {
	case strings.Contains(proc, "sshd") && strings.Contains(msg, "Accepted"):
		e.EventType = models.AuthEventSSHSuccess
		e = parseSSHLoginEvent(e, e.RawLine)
	case strings.Contains(proc, "sshd") && (strings.Contains(msg, "Failed") || strings.Contains(msg, "Invalid")):
		e.EventType = models.AuthEventSSHFailed
		e.Level = "ERROR"
		e = parseSSHLoginEvent(e, e.RawLine)
	case strings.Contains(proc, "sshd"):
		e.EventType = models.AuthEventSecurity
	case strings.Contains(proc, "login") || strings.Contains(proc, "shutdown") || strings.Contains(proc, "reboot") || strings.Contains(proc, "init"):
		e.EventType = models.AuthEventLogin
	default:
		e.EventType = models.AuthEventSecurity
	}
	return e
}

// parseAuthLogLine parses a single auth.log line into a structured entry
func parseAuthLogLine(line string) (models.AuthLogEntry, error) {
	entry := models.AuthLogEntry{
		RawLine: line,
		Level:   "INFO", // Default level
	}

	// Parse timestamp and hostname (format: 2025-10-23T13:13:36.578618+09:00 nozomi-TKB)
	timestampRegex := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(\S+)`)
	if matches := timestampRegex.FindStringSubmatch(line); matches != nil {
		if t, err := time.Parse(time.RFC3339Nano, matches[1]); err == nil {
			entry.Timestamp = t
		}
		entry.Hostname = matches[2]
	}

	// Parse process and PID (format: sudo[15679])
	processRegex := regexp.MustCompile(`\s+(\S+?)\[(\d+)\]\s*:`)
	if matches := processRegex.FindStringSubmatch(line); matches != nil {
		entry.Process = matches[1]
		entry.PID = matches[2]
	}

	// Classify and parse based on event type
	entry = classifyAndParseAuthEvent(entry, line)

	return entry, nil
}

// classifyAndParseAuthEvent classifies the auth event type and extracts specific fields
func classifyAndParseAuthEvent(entry models.AuthLogEntry, line string) models.AuthLogEntry {
	// Sudo commands
	if strings.Contains(line, "sudo") && strings.Contains(line, "USER=") && strings.Contains(line, "COMMAND=") {
		entry.EventType = models.AuthEventSudo
		entry.Level = "WARNING" // Sudo usage is noteworthy
		entry = parseSudoEvent(entry, line)
		return entry
	}

	// SSH successful login
	if strings.Contains(line, "sshd") && strings.Contains(line, "Accepted") {
		entry.EventType = models.AuthEventSSHSuccess
		entry = parseSSHLoginEvent(entry, line)
		return entry
	}

	// SSH failed login
	if strings.Contains(line, "sshd") && strings.Contains(line, "Failed") {
		entry.EventType = models.AuthEventSSHFailed
		entry.Level = "ERROR" // Failed attempts are errors
		entry = parseSSHLoginEvent(entry, line)
		return entry
	}

	// Login events
	if strings.Contains(line, "login") && (strings.Contains(line, "session opened") || strings.Contains(line, "session closed")) {
		entry.EventType = models.AuthEventLogin
		entry = parseLoginEvent(entry, line)
		return entry
	}

	// Authentication failures
	if strings.Contains(line, "authentication failure") {
		entry.EventType = models.AuthEventAuthFailure
		entry.Level = "ERROR"
		entry = parseAuthFailureEvent(entry, line)
		return entry
	}

	// Other security events
	if strings.Contains(line, "security") || strings.Contains(line, "SECURITY") || strings.Contains(line, "violation") {
		entry.EventType = models.AuthEventSecurity
		entry.Level = "ERROR"
		return entry
	}

	// Default to other
	entry.EventType = models.AuthEventOther
	return entry
}

// parseSudoEvent extracts fields from sudo command lines
func parseSudoEvent(entry models.AuthLogEntry, line string) models.AuthLogEntry {
	// Extract user before the colon (format: n2os-ids : PWD=...)
	userRegex := regexp.MustCompile(`\s+(\S+)\s+:\s+PWD=`)
	if matches := userRegex.FindStringSubmatch(line); matches != nil {
		entry.User = matches[1]
	}

	// Extract sudo target user (format: USER=root)
	sudoUserRegex := regexp.MustCompile(`USER=(\S+)`)
	if matches := sudoUserRegex.FindStringSubmatch(line); matches != nil {
		entry.SudoUser = matches[1]
	}

	// Extract command (format: COMMAND=/usr/local/sbin/dmidecode -t bios)
	commandRegex := regexp.MustCompile(`COMMAND=(.+)`)
	if matches := commandRegex.FindStringSubmatch(line); matches != nil {
		entry.Command = matches[1]
	}

	// Extract working directory (format: PWD=/usr/local/ids-webconsole)
	pwdRegex := regexp.MustCompile(`PWD=(\S+)`)
	if matches := pwdRegex.FindStringSubmatch(line); matches != nil {
		// Include PWD in message for context
		entry.Message = fmt.Sprintf("PWD=%s COMMAND=%s", matches[1], entry.Command)
	} else {
		entry.Message = fmt.Sprintf("COMMAND=%s", entry.Command)
	}

	return entry
}

// parseSSHLoginEvent extracts fields from SSH login events
func parseSSHLoginEvent(entry models.AuthLogEntry, line string) models.AuthLogEntry {
	// Extract user (format: for user from)
	userRegex := regexp.MustCompile(`for\s+(\S+)\s+from`)
	if matches := userRegex.FindStringSubmatch(line); matches != nil {
		entry.User = matches[1]
	}

	// Extract source IP (format: from 192.168.1.1)
	ipRegex := regexp.MustCompile(`from\s+(\S+)`)
	if matches := ipRegex.FindStringSubmatch(line); matches != nil {
		entry.SourceIP = matches[1]
	}

	// Extract authentication method if present
	if strings.Contains(line, "publickey") {
		entry.Message = "SSH publickey authentication"
	} else if strings.Contains(line, "password") {
		entry.Message = "SSH password authentication"
	} else {
		entry.Message = "SSH authentication"
	}

	if entry.EventType == models.AuthEventSSHFailed {
		entry.Message += " failed"
	} else {
		entry.Message += " successful"
	}

	return entry
}

// parseLoginEvent extracts fields from login events
func parseLoginEvent(entry models.AuthLogEntry, line string) models.AuthLogEntry {
	// Extract user (format: login[PID]: ROOT LOGIN (root) ON ttyv0)
	userRegex := regexp.MustCompile(`\((\S+)\)`)
	if matches := userRegex.FindStringSubmatch(line); matches != nil {
		entry.User = matches[1]
	}

	// Extract session info
	if strings.Contains(line, "session opened") {
		entry.Message = "Login session opened"
	} else if strings.Contains(line, "session closed") {
		entry.Message = "Login session closed"
	}

	return entry
}

// parseAuthFailureEvent extracts fields from authentication failure events
func parseAuthFailureEvent(entry models.AuthLogEntry, line string) models.AuthLogEntry {
	// Extract user from authentication failure
	userRegex := regexp.MustCompile(`user=(\S+)`)
	if matches := userRegex.FindStringSubmatch(line); matches != nil {
		entry.User = matches[1]
	}

	entry.Message = "Authentication failure"
	return entry
}

// sortAuthLogsByTimestamp sorts auth logs by timestamp (most recent first)
func sortAuthLogsByTimestamp(entries []models.AuthLogEntry) {
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
}

// FindLatestSupportArchiveTime finds the latest timestamp of /usr/local/sbin/n2os-asksupport command
func FindLatestSupportArchiveTime(dir string) (time.Time, error) {
	authLogPath := filepath.Join(resolveLogDir(dir), "auth.log")
	file, err := os.Open(authLogPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open auth.log: %w", err)
	}
	defer file.Close()

	var latestTime time.Time
	scanner := bufio.NewScanner(file)
	supportCommand := "/usr/local/sbin/n2os-asksupport"

	for scanner.Scan() {
		line := scanner.Text()

		// Check if this line contains the support command
		if strings.Contains(line, supportCommand) {
			// Parse timestamp (format: 2025-10-23T13:13:36.578618+09:00)
			timestampRegex := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})`)
			if matches := timestampRegex.FindStringSubmatch(line); matches != nil {
				if t, err := time.Parse(time.RFC3339Nano, matches[1]); err == nil {
					// Convert to UTC
					utcTime := t.UTC()
					if utcTime.After(latestTime) {
						latestTime = utcTime
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return time.Time{}, fmt.Errorf("error reading auth.log: %w", err)
	}

	return latestTime, nil
}
