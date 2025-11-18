package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"penny/internal/models"
	"time"
)

// Syslog timestamp format: 2025-03-17T09:16:17.815995+00:00
var syslogRegex = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s+(.*)$`)

// ParseSyslog parses BSD syslog format messages
func ParseSyslog(filePath string) ([]models.LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // File doesn't exist, not an error
		}
		return nil, err
	}
	defer file.Close()

	var entries []models.LogEntry
	scanner := bufio.NewScanner(file)

	// Increase buffer size for long log lines
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseSyslogLine(line)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseSyslogLine(line string) *models.LogEntry {
	// Split into timestamp and rest
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return &models.LogEntry{
			RawLine: line,
			Message: line,
		}
	}

	// Parse timestamp (RFC3339 with fractional seconds)
	timestamp, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		// Try without timezone
		timestamp, _ = time.Parse("2006-01-02T15:04:05.999999", parts[0])
	}

	hostname := parts[1]
	rest := parts[3]

	// Extract process name and PID
	var process, pid, message string

	// Try to match: process[pid] message or process message
	if idx := strings.Index(rest, "["); idx != -1 {
		process = rest[:idx]
		if endIdx := strings.Index(rest[idx:], "]"); endIdx != -1 {
			pid = rest[idx+1 : idx+endIdx]
			if len(rest) > idx+endIdx+1 {
				message = strings.TrimSpace(rest[idx+endIdx+2:])
			}
		}
	} else {
		// No PID, split on first space
		if idx := strings.Index(rest, " "); idx != -1 {
			process = rest[:idx]
			message = strings.TrimSpace(rest[idx+1:])
		} else {
			process = rest
		}
	}

	// Determine log level from message content
	level := detectLevel(message)

	return &models.LogEntry{
		Timestamp: timestamp,
		Hostname:  hostname,
		Process:   process,
		PID:       pid,
		Message:   message,
		Level:     level,
		RawLine:   line,
	}
}

func detectLevel(message string) string {
	msgLower := strings.ToLower(message)

	if strings.Contains(msgLower, "fatal") || strings.Contains(msgLower, "panic") {
		return "FATAL"
	}
	if strings.Contains(msgLower, "error") || strings.Contains(msgLower, "err:") {
		return "ERROR"
	}
	if strings.Contains(msgLower, "warning") || strings.Contains(msgLower, "warn") {
		return "WARNING"
	}
	if strings.Contains(msgLower, "critical") || strings.Contains(msgLower, "crit") {
		return "CRITICAL"
	}

	return "INFO"
}

// ParseMessagesLog is a convenience function for parsing data/log/messages
func ParseMessagesLog(baseDir string) ([]models.LogEntry, error) {
	messagesPath := filepath.Join(baseDir, "data", "log", "messages")
	return ParseSyslog(messagesPath)
}
