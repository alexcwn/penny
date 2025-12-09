package parser

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ParseN2OSProductionLogs parses all production.log files (including rotated logs)
func ParseN2OSProductionLogs(baseDir string, data *models.ArchiveData) error {
	logDir := filepath.Join(baseDir, "data", "log", "n2os")

	// Get timezone from metadata (already parsed by ParseN2OSConf)
	timezone := data.Metadata.Timezone
	if timezone == "" {
		timezone = "UTC" // Fallback
	}

	var allEntries []models.N2OSProductionLogEntry

	// Parse rotated gzip logs in reverse order (oldest first: production.log.0.gz -> latest)
	for i := 9; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("production.log.%d.gz", i))
		if entries, err := parseN2OSProductionLogFile(logPath, true, timezone); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "production.log")
	if entries, err := parseN2OSProductionLogFile(currentLogPath, false, timezone); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSProductionLogs = allEntries

	return nil
}

// parseN2OSProductionLogFile parses a single production.log file (gzipped or plain)
func parseN2OSProductionLogFile(path string, isGzipped bool, timezone string) ([]models.N2OSProductionLogEntry, error) {
	var file *os.File
	var scanner *bufio.Scanner
	var err error

	if isGzipped {
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()

		scanner = bufio.NewScanner(gzReader)
	} else {
		file, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner = bufio.NewScanner(file)
	}

	// Extract source from filename
	// "production.log" -> "production"
	// "production.log.0.gz" -> "production.0"
	filename := filepath.Base(path)
	source := extractProductionSourceFromFilename(filename)

	var entries []models.N2OSProductionLogEntry
	// Example: W, [2025-11-13T13:35:21.934813 #4923]  WARN -- : Directory checksums cache file write failed...
	logLineRegex := regexp.MustCompile(`^([A-Z]), \[([^\]]+)\s+#(\d+)\]\s+([A-Z]+)\s+--\s+:\s+(.*)$`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		matches := logLineRegex.FindStringSubmatch(line)
		if len(matches) > 5 {
			// Line matches the production.log format
			lineNumber++

			entry := models.N2OSProductionLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
				ProcessID:  matches[3], // PID
				Level:      matches[4],  // Log level (WARN, INFO, ERROR, DEBUG)
				Message:    matches[5],  // Message
			}

			// Parse timestamp from matches[2]: "2025-11-13T13:35:21.934813"
			if ts, err := parseProductionTimestamp(matches[2], timezone); err == nil {
				entry.Timestamp = ts
			}

			entries = append(entries, entry)
		} else {
			// Line has NO timestamp - append to previous entry (multiline continuation)
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n " + line
				entries[len(entries)-1].Message += "\n " + line
			}
			// If there's no previous entry, skip this line (orphaned continuation line)
		}
	}

	return entries, scanner.Err()
}

// parseProductionTimestamp parses timestamps in production.log format using the specified timezone
// Example: 2025-11-13T13:35:21.934813
func parseProductionTimestamp(ts string, timezone string) (time.Time, error) {
	// Load timezone location
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		// Fallback to UTC if timezone is invalid
		loc = time.UTC
	}

	// Try parsing with microseconds in the specified timezone
	t, err := time.ParseInLocation("2006-01-02T15:04:05.000000", ts, loc)
	if err == nil {
		return t, nil
	}

	// Try without microseconds
	t, err = time.ParseInLocation("2006-01-02T15:04:05", ts, loc)
	if err == nil {
		return t, nil
	}

	return time.Time{}, err
}

// extractProductionSourceFromFilename converts a log filename to its source identifier
// "production.log" -> "production"
// "production.log.0.gz" -> "production.0"
// "production.log.0" -> "production.0"
func extractProductionSourceFromFilename(filename string) string {
	// Remove ".gz" extension if present
	if strings.HasSuffix(filename, ".gz") {
		filename = strings.TrimSuffix(filename, ".gz")
	}

	// Handle main log
	if filename == "production.log" {
		return "production"
	}

	// Handle rotated logs: "production.log.0" -> "production.0"
	if strings.HasPrefix(filename, "production.log.") {
		suffix := strings.TrimPrefix(filename, "production.log.")
		return "production." + suffix
	}

	// Fallback
	return "production"
}
