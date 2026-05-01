package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"sort"
	"strings"
	"time"
)

// ParseN2OSOtelcolLogs parses all n2os_otelcol.log files (including bz2-compressed rotated logs)
func ParseN2OSOtelcolLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	var allEntries []models.N2OSOtelcolLogEntry

	// Parse rotated compressed logs in reverse order (oldest first: .5.bz2 -> .0.bz2)
	for i := 5; i >= 0; i-- {
		bz2Path := filepath.Join(logDir, fmt.Sprintf("n2os_otelcol.log.%d.bz2", i))
		if _, err := os.Stat(bz2Path); os.IsNotExist(err) {
			continue
		}
		extractedPath, err := extractBz2InPlace(bz2Path)
		if err != nil {
			continue
		}
		if entries, err := parseN2OSOtelcolLogFile(extractedPath, fmt.Sprintf("otelcol.%d", i)); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	// Parse current (uncompressed) log last (newest)
	currentLogPath := filepath.Join(logDir, "n2os_otelcol.log")
	if entries, err := parseN2OSOtelcolLogFile(currentLogPath, "otelcol"); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSOtelcolLogs = allEntries

	return nil
}

// parseN2OSOtelcolLogFile parses a single n2os_otelcol.log file.
// Format (tab-separated): TIMESTAMP\tLEVEL\tCALLER\tMESSAGE[\tFIELDS_JSON]
// Example: 2026-04-19T13:15:00.379Z\terror\tinternal/queue_sender.go:50\tExporting failed.\t{"key":"val",...}
// Continuation lines (stack traces without a timestamp) are appended to the previous entry.
func parseN2OSOtelcolLogFile(path, source string) ([]models.N2OSOtelcolLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.N2OSOtelcolLogEntry

	// Use a large scanner buffer — some lines with big JSON blobs can be long
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		lineNumber++

		ts, level, caller, msg, fields, ok := parseOtelcolLine(line)
		if !ok {
			// No timestamp — continuation line (stack trace), append to previous
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
				entries[len(entries)-1].Message += "\n" + line
			}
			continue
		}

		entries = append(entries, models.N2OSOtelcolLogEntry{
			Timestamp:  ts,
			Level:      level,
			Caller:     caller,
			Message:    msg,
			Fields:     fields,
			Source:     source,
			LineNumber: lineNumber,
			RawLine:    line,
		})
	}

	return entries, scanner.Err()
}

// parseOtelcolLine parses a single otelcol tab-separated log line.
// Returns (timestamp, level, caller, message, fields, ok).
func parseOtelcolLine(line string) (ts time.Time, level, caller, msg, fields string, ok bool) {
	parts := strings.SplitN(line, "\t", 5)
	if len(parts) < 3 {
		return
	}

	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		// Also try RFC3339 without nanoseconds
		t, err = time.Parse(time.RFC3339, parts[0])
		if err != nil {
			return
		}
	}

	ts = t
	level = parts[1]
	ok = true

	if len(parts) >= 3 {
		caller = parts[2]
	}
	if len(parts) >= 4 {
		msg = parts[3]
	}
	if len(parts) >= 5 {
		fields = parts[4]
	}
	return
}
