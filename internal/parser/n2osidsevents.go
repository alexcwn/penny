package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ParseN2OSIDSEventsLogs parses all n2os_ids_events.log files (including rotated logs)
func ParseN2OSIDSEventsLogs(baseDir string, data *models.ArchiveData) error {
	logDir := filepath.Join(baseDir, "data", "log", "n2os")

	var allEntries []models.N2OSIDSEventsLogEntry

	// Parse rotated logs in reverse order (oldest first: n2os_ids_events.log.4 -> n2os_ids_events.log.0)
	for i := 4; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("n2os_ids_events.log.%d", i))
		if entries, err := parseN2OSIDSEventsLogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "n2os_ids_events.log")
	if entries, err := parseN2OSIDSEventsLogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSIDSEventsLogs = allEntries

	return nil
}

// parseN2OSIDSEventsLogFile parses a single n2os_ids_events.log file
func parseN2OSIDSEventsLogFile(path string) ([]models.N2OSIDSEventsLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Extract source from filename
	// "n2os_ids_events.log" -> "events"
	// "n2os_ids_events.log.0" -> "events.0"
	// "n2os_ids_events.log.1" -> "events.1"
	filename := filepath.Base(path)
	source := extractIDSEventsSourceFromFilename(filename)

	var entries []models.N2OSIDSEventsLogEntry
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing
	// Example: [2025-09-29T21:26:32.782 +0200] n2os_ids[91033][598998] EVENT:[dce-rpc] Exception caught: St13runtime_error/PAYLOAD EXCEPTION...
	timestampRegex := regexp.MustCompile(`^\[([^\]]+)\]`)
	headerRegex := regexp.MustCompile(`n2os_ids\[(\d+)\]\[(\d+)\]\s+EVENT:\[([^\]]+)\](.*)`)

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

			entry := models.N2OSIDSEventsLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			// Parse timestamp
			// Format: 2025-09-29T21:26:32.782 +0200
			if ts, err := parseN2OSIDSEventsTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}

			// Extract PID, ThreadID, Protocol, and Event
			headerMatch := headerRegex.FindStringSubmatch(line)
			if len(headerMatch) > 4 {
				entry.ProcessID = headerMatch[1]
				entry.ThreadID = headerMatch[2]
				entry.Protocol = headerMatch[3]
				entry.Event = strings.TrimSpace(headerMatch[4])
			}

			entries = append(entries, entry)
		} else {
			// Line has NO timestamp - append to previous entry
			if len(entries) > 0 {
				// Append to the RawLine of the last entry with a newline
				entries[len(entries)-1].RawLine += "\n" + line
				// Also append to the Event field
				entries[len(entries)-1].Event += "\n" + line
			}
			// If there's no previous entry, skip this line (orphaned continuation line)
		}
	}

	return entries, scanner.Err()
}

// parseN2OSIDSEventsTimestamp parses timestamps in n2os_ids_events format
// Example: 2025-09-29T21:26:32.782 +0200
func parseN2OSIDSEventsTimestamp(ts string) (time.Time, error) {
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

// extractIDSEventsSourceFromFilename converts a log filename to its source identifier
// "n2os_ids_events.log" -> "events"
// "n2os_ids_events.log.0" -> "events.0"
// "n2os_ids_events.log.1" -> "events.1"
func extractIDSEventsSourceFromFilename(filename string) string {
	// Remove "n2os_ids_events" prefix and ".log" extension
	if filename == "n2os_ids_events.log" {
		return "events"
	}

	// Handle rotated logs: "n2os_ids_events.log.0" -> "events.0"
	if strings.HasPrefix(filename, "n2os_ids_events.log.") {
		suffix := strings.TrimPrefix(filename, "n2os_ids_events.log.")
		return "events." + suffix
	}

	// Fallback (shouldn't happen with standard log rotation)
	return "events"
}
