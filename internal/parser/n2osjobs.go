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

// compareJobSources returns true if sourceA should come before sourceB
// Order: jobs.4 < jobs.3 < jobs.2 < jobs.1 < jobs.0 < jobs
// (older rotated logs first in chronological order)
func compareJobSources(sourceA, sourceB string) bool {
	// Extract rotation number if present
	extractNum := func(s string) int {
		if s == "jobs" {
			return -1 // Current log comes last
		}
		// Parse "jobs.N" -> N (e.g., "jobs.0" -> 0)
		parts := strings.Split(s, ".")
		if len(parts) == 2 {
			if num, err := strconv.Atoi(parts[1]); err == nil {
				return num
			}
		}
		return -1
	}

	numA := extractNum(sourceA)
	numB := extractNum(sourceB)

	// Higher rotation numbers (older files) come first in chronological order
	return numA > numB
}

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

	// Sort all entries by timestamp, then source file, then line number for stable chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		// Primary: Sort by timestamp
		if !allEntries[i].Timestamp.Equal(allEntries[j].Timestamp) {
			return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
		}

		// Secondary: Sort by source file (older rotated logs first)
		if allEntries[i].Source != allEntries[j].Source {
			return compareJobSources(allEntries[i].Source, allEntries[j].Source)
		}

		// Tertiary: Sort by line number within same file
		return allEntries[i].LineNumber < allEntries[j].LineNumber
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
	// Header format: # Logfile created on 2025-10-01 13:58:10 +0200 by logger.rb/v1.7.0
	headerRegex := regexp.MustCompile(`^# Logfile created on (.+?) by`)
	executedRegex := regexp.MustCompile(`(IDSApi::[A-Za-z:]+Task) executed in ([\d.]+)ms`)

	// Line number counter (only increments for lines with timestamps)
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Check for header line first
		headerMatch := headerRegex.FindStringSubmatch(line)
		if len(headerMatch) > 1 {
			// Line is a log file header - create new entry
			lineNumber++

			entry := models.N2OSJobLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			// Parse header timestamp format: "2025-10-01 13:58:10 +0200"
			if ts, err := parseLogHeaderTimestamp(headerMatch[1]); err == nil {
				entry.Timestamp = ts
			}

			entries = append(entries, entry)
			continue
		}

		// Parse regular log timestamp to determine if this is a new entry or continuation
		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			// Line has timestamp - create new entry
			lineNumber++

			entry := models.N2OSJobLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			// Parse timestamp
			if ts, err := parseN2OSJobTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
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
		} else {
			// Line has NO timestamp - append to previous entry
			if len(entries) > 0 {
				// Append to the RawLine of the last entry with a newline
				entries[len(entries)-1].RawLine += "\n" + line
			}
			// If there's no previous entry, skip this line (orphaned continuation line)
		}
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

// parseLogHeaderTimestamp parses timestamps in log file header format
// Example: 2025-10-01 13:58:10 +0200
func parseLogHeaderTimestamp(ts string) (time.Time, error) {
	// Header format: "2025-10-01 13:58:10 +0200"
	t, err := time.Parse("2006-01-02 15:04:05 -0700", ts)
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
