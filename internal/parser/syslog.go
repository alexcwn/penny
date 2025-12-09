package parser

import (
	"bufio"
	"compress/bzip2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"penny/internal/models"
	"time"
)

// Syslog timestamp format: 2025-03-17T09:16:17.815995+00:00
var syslogRegex = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s+(.*)$`)

// openFileWithDecompression opens a file and returns a reader that automatically
// decompresses bzip2 files based on file extension
func openFileWithDecompression(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Check if file is bzip2 compressed by extension
	if strings.HasSuffix(path, ".bz2") {
		return &readCloserWrapper{
			Reader: bzip2.NewReader(file),
			Closer: file,
		}, nil
	}

	return file, nil
}

// readCloserWrapper combines an io.Reader with an io.Closer
type readCloserWrapper struct {
	io.Reader
	io.Closer
}

// ParseSyslogFile is the public function that opens and parses a syslog file
// Supports both uncompressed and bzip2-compressed files
func ParseSyslogFile(filePath string) ([]models.LogEntry, error) {
	file, err := openFileWithDecompression(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // File doesn't exist, not an error
		}
		return nil, err
	}
	defer file.Close()

	return parseSyslogReader(file)
}

// parseSyslogReader parses syslog entries from an io.Reader
func parseSyslogReader(reader io.Reader) ([]models.LogEntry, error) {
	var entries []models.LogEntry
	scanner := bufio.NewScanner(reader)

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

// ParseSyslog parses BSD syslog format messages (deprecated: use ParseSyslogFile instead)
func ParseSyslog(filePath string) ([]models.LogEntry, error) {
	return ParseSyslogFile(filePath)
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

// ParseMessagesLog parses all messages log files (including compressed rotated logs)
func ParseMessagesLog(baseDir string) ([]models.LogEntry, error) {
	logDir := filepath.Join(baseDir, "data", "log")
	var allEntries []models.LogEntry

	// Parse rotated compressed logs in reverse order (oldest first: messages.6.bz2 -> messages.0.bz2)
	// Iterate up to 10 to be safe if there are more rotated logs
	for i := 10; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("messages.%d.bz2", i))
		if entries, err := ParseSyslogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current uncompressed log last (newest)
	currentLogPath := filepath.Join(logDir, "messages")
	if entries, err := ParseSyslogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	return allEntries, nil
}
