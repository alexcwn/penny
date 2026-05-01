package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ParseN2OSIDSLogs parses all n2os_ids.log files (including rotated logs)
func ParseN2OSIDSLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_ids.log", 5, parseN2OSIDSLogFile)


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
	source := extractLogSource(filename, "n2os_ids.log", "ids")

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
			if ts, err := parseN2OSTimestamp(timestampMatch[1]); err == nil {
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
