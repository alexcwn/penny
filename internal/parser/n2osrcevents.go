package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
)

// ParseN2OSRCEventsLogs parses all n2os_rc_events.log files (including rotated logs)
func ParseN2OSRCEventsLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_rc_events.log", 4, parseN2OSRCEventsLogFile)


	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSRCEventsLogs = allEntries

	return nil
}

// parseN2OSRCEventsLogFile parses a single n2os_rc_events.log file
func parseN2OSRCEventsLogFile(path string) ([]models.N2OSRCEventsLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2os_rc_events.log", "rc_events")

	var entries []models.N2OSRCEventsLogEntry
	scanner := bufio.NewScanner(file)

	// Example: [2026-04-14T02:49:05.289 +0000] n2os_rc[22][731690] EVENT: {"Trace_Forwarding_Queue":{...}}
	timestampRegex := regexp.MustCompile(`^\[([^\]]+)\]`)
	headerRegex := regexp.MustCompile(`n2os_rc\[(\d+)\]\[(\d+)\]\s+EVENT:(.*)`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			lineNumber++

			entry := models.N2OSRCEventsLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			if ts, err := parseN2OSTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}

			headerMatch := headerRegex.FindStringSubmatch(line)
			if len(headerMatch) > 3 {
				entry.ProcessID = headerMatch[1]
				entry.ThreadID = headerMatch[2]
				entry.Event = strings.TrimSpace(headerMatch[3])
			}

			entries = append(entries, entry)
		} else {
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
				entries[len(entries)-1].Event += "\n" + line
			}
		}
	}

	return entries, scanner.Err()
}
