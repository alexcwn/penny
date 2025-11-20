package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strings"
	"time"
)

// ParseAuthLog parses the auth.log file and returns structured auth log entries
func ParseAuthLog(dir string) ([]models.AuthLogEntry, error) {
	authLogPath := filepath.Join(dir, "data", "log", "auth.log")
	file, err := os.Open(authLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open auth.log: %w", err)
	}
	defer file.Close()

	var entries []models.AuthLogEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseAuthLogLine(line)
		if err != nil {
			// Skip lines that can't be parsed rather than failing entirely
			continue
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading auth.log: %w", err)
	}

	// Sort by timestamp (most recent first)
	sortAuthLogsByTimestamp(entries)

	return entries, nil
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
	authLogPath := filepath.Join(dir, "data", "log", "auth.log")
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
