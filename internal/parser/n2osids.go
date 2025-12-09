package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ParseN2OSIDSLogs parses all n2os_ids.log files (including rotated logs)
func ParseN2OSIDSLogs(baseDir string, data *models.ArchiveData) error {
	logDir := filepath.Join(baseDir, "data", "log", "n2os")

	var allEntries []models.N2OSIDSLogEntry

	// Parse rotated logs in reverse order (oldest first: n2os_ids.log.5 -> n2os_ids.log.0)
	for i := 5; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("n2os_ids.log.%d", i))
		if entries, err := parseN2OSIDSLogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "n2os_ids.log")
	if entries, err := parseN2OSIDSLogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSIDSLogs = allEntries

	// Extract Network elements limit from log entries
	extractNetworkElementLimit(allEntries, data)

	return nil
}

// parseN2OSIDSLogFile parses a single n2os_ids.log file
func parseN2OSIDSLogFile(path string) ([]models.N2OSIDSLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Extract source from filename
	// "n2os_ids.log" -> "ids"
	// "n2os_ids.log.0" -> "ids.0"
	// "n2os_ids.log.1" -> "ids.1"
	filename := filepath.Base(path)
	source := extractIDSSourceFromFilename(filename)

	var entries []models.N2OSIDSLogEntry
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing
	// Example: [2025-10-01T08:02:08.280 +0200] n2os_ids[91033][599027] DEBUG: fetching assets:jobs_sync - updated: 259, to check: 44
	timestampRegex := regexp.MustCompile(`^\[([^\]]+)\]`)
	headerRegex := regexp.MustCompile(`n2os_ids\[(\d+)\]\[(\d+)\]\s+([A-Z]+):(.*)`)

	// Line number counter (only increments for lines with timestamps)
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse timestamp to determine if this is a new entry or continuation
		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			// Line has timestamp - create new entry
			lineNumber++

			entry := models.N2OSIDSLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			// Parse timestamp
			// Format: 2025-10-01T08:02:08.280 +0200
			if ts, err := parseN2OSIDSTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}

			// Extract PID, ThreadID, Level, and Message
			headerMatch := headerRegex.FindStringSubmatch(line)
			if len(headerMatch) > 4 {
				entry.ProcessID = headerMatch[1]
				entry.ThreadID = headerMatch[2]
				entry.Level = headerMatch[3]
				entry.Message = strings.TrimSpace(headerMatch[4])
			}

			entries = append(entries, entry)
		} else {
			// Line has NO timestamp - append to previous entry
			if len(entries) > 0 {
				// Append to the RawLine of the last entry with a newline
				entries[len(entries)-1].RawLine += "\n" + line
				// Also append to the Message field
				entries[len(entries)-1].Message += "\n" + line
			}
			// If there's no previous entry, skip this line (orphaned continuation line)
		}
	}

	return entries, scanner.Err()
}

// parseN2OSIDSTimestamp parses timestamps in n2os_ids format
// Example: 2025-10-01T08:02:08.280 +0200
func parseN2OSIDSTimestamp(ts string) (time.Time, error) {
	// Try parsing with milliseconds and timezone
	t, err := time.Parse("2006-01-02T15:04:05.000 -0700", ts)
	if err == nil {
		return t, nil
	}

	// Try without milliseconds
	t, err = time.Parse("2006-01-02T15:04:05 -0700", ts)
	if err == nil {
		return t, nil
	}

	return time.Time{}, err
}

// extractIDSSourceFromFilename converts a log filename to its source identifier
// "n2os_ids.log" -> "ids"
// "n2os_ids.log.0" -> "ids.0"
// "n2os_ids.log.1" -> "ids.1"
func extractIDSSourceFromFilename(filename string) string {
	// Remove "n2os_ids" prefix and ".log" extension
	if filename == "n2os_ids.log" {
		return "ids"
	}

	// Handle rotated logs: "n2os_ids.log.0" -> "ids.0"
	if strings.HasPrefix(filename, "n2os_ids.log.") {
		suffix := strings.TrimPrefix(filename, "n2os_ids.log.")
		return "ids." + suffix
	}

	// Fallback (shouldn't happen with standard log rotation)
	return "ids"
}

// extractNetworkElementLimit scans log entries for the Network elements limit value
func extractNetworkElementLimit(entries []models.N2OSIDSLogEntry, data *models.ArchiveData) {
	// Regex to match: "Network elements limit = 125999"
	limitRegex := regexp.MustCompile(`Network elements limit\s*=\s*(\d+)`)

	// Scan entries in reverse (newest first) to get the most recent value
	for i := len(entries) - 1; i >= 0; i-- {
		match := limitRegex.FindStringSubmatch(entries[i].Message)
		if len(match) > 1 {
			if limit, err := strconv.Atoi(match[1]); err == nil {
				data.SystemInfo.NodeElementLimit = limit
				return // Found it, stop searching
			}
		}
	}
}
