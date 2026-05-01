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

// ParseN2OSRCLogs parses all n2os_rc.log files (including rotated logs)
func ParseN2OSRCLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_rc.log", 5, parseN2OSRCLogFile)


	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSRCLogs = allEntries

	return nil
}

// parseN2OSRCLogFile parses a single n2os_rc.log file
func parseN2OSRCLogFile(path string) ([]models.N2OSRCLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2os_rc.log", "rc")

	var entries []models.N2OSRCLogEntry
	scanner := bufio.NewScanner(file)

	// Example: [2026-04-14T02:22:59.348 +0000] n2os_rc[22][100584] INFO: message text
	timestampRegex := regexp.MustCompile(`^\[([^\]]+)\]`)
	headerRegex := regexp.MustCompile(`n2os_rc\[(\d+)\]\[(\d+)\]\s+([A-Z]+):(.*)`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			lineNumber++

			entry := models.N2OSRCLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}

			if ts, err := parseN2OSTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}

			headerMatch := headerRegex.FindStringSubmatch(line)
			if len(headerMatch) > 4 {
				entry.ProcessID = headerMatch[1]
				entry.ThreadID = headerMatch[2]
				entry.Level = headerMatch[3]
				entry.Message = strings.TrimSpace(headerMatch[4])
			}

			entries = append(entries, entry)
		} else {
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
				entries[len(entries)-1].Message += "\n" + line
			}
		}
	}

	return entries, scanner.Err()
}
