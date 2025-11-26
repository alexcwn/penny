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

// ParseN2OSJobLogs parses all n2osjobs.log files (including rotated logs)
func ParseN2OSJobLogs(baseDir string, data *models.ArchiveData) error {
	logDir := filepath.Join(baseDir, "data", "log", "n2os")

	var allEntries []models.N2OSJobLogEntry

	// Parse rotated logs in reverse order (oldest first: n2osjobs.log.4 -> n2osjobs.log.0)
	for i := 4; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("n2osjobs.log.%d", i))
		if entries, err := parseN2OSJobLogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "n2osjobs.log")
	if entries, err := parseN2OSJobLogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSJobLogs = allEntries

	return nil
}

// parseN2OSJobLogFile parses a single n2osjobs.log file
func parseN2OSJobLogFile(path string) ([]models.N2OSJobLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Extract source from filename
	// "n2osjobs.log" -> "jobs"
	// "n2osjobs.log.0" -> "jobs.0"
	// "n2osjobs.log.1" -> "jobs.1"
	filename := filepath.Base(path)
	source := extractSourceFromFilename(filename)

	var entries []models.N2OSJobLogEntry
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing
	// Example: I, [2025-11-26T01:53:16+00:00  #53354]  INFO -- : IDSApi::CMC::SyncTask executed in 1900.083ms
	timestampRegex := regexp.MustCompile(`^[A-Z], \[([^\]]+)\]`)
	executedRegex := regexp.MustCompile(`(IDSApi::[A-Za-z:]+Task) executed in ([\d.]+)ms`)

	// Cache to hold the last valid timestamp for entries without timestamps
	var lastTimestamp time.Time

	// Line number counter (counts non-empty lines only)
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Increment line number for each non-empty line
		lineNumber++

		entry := models.N2OSJobLogEntry{
			RawLine:    line,
			Source:     source,
			LineNumber: lineNumber,
		}

		// Parse timestamp
		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			if ts, err := parseN2OSJobTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
				lastTimestamp = ts // Cache this timestamp for subsequent lines
			}
		} else if !lastTimestamp.IsZero() {
			// No timestamp found, use cached timestamp from previous entry
			entry.Timestamp = lastTimestamp
		}

		// Extract task name and duration from "executed in" lines
		executedMatch := executedRegex.FindStringSubmatch(line)
		if len(executedMatch) > 2 {
			entry.TaskName = executedMatch[1]
			if duration, err := strconv.ParseFloat(executedMatch[2], 64); err == nil {
				entry.DurationMS = duration
			}
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// parseN2OSJobTimestamp parses timestamps in Ruby logger format
// Example: 2025-11-26T01:53:16+00:00  #53354
func parseN2OSJobTimestamp(ts string) (time.Time, error) {
	// Remove PID and extra spaces after timezone
	// "2025-11-26T01:53:16+00:00  #53354" -> "2025-11-26T01:53:16+00:00"
	parts := strings.Fields(ts)
	if len(parts) > 0 {
		ts = parts[0]
	}

	// Try parsing with timezone
	t, err := time.Parse("2006-01-02T15:04:05-07:00", ts)
	if err == nil {
		return t, nil
	}

	// Try without milliseconds
	t, err = time.Parse("2006-01-02T15:04:05.000-07:00", ts)
	if err == nil {
		return t, nil
	}

	return time.Time{}, err
}

// extractSourceFromFilename converts a log filename to its source identifier
// "n2osjobs.log" -> "jobs"
// "n2osjobs.log.0" -> "jobs.0"
// "n2osjobs.log.1" -> "jobs.1"
func extractSourceFromFilename(filename string) string {
	// Remove "n2os" prefix and ".log" extension
	// "n2osjobs.log" -> "jobs"
	if filename == "n2osjobs.log" {
		return "jobs"
	}

	// Handle rotated logs: "n2osjobs.log.0" -> "jobs.0"
	if strings.HasPrefix(filename, "n2osjobs.log.") {
		suffix := strings.TrimPrefix(filename, "n2osjobs.log.")
		return "jobs." + suffix
	}

	// Fallback (shouldn't happen with standard log rotation)
	return "jobs"
}
