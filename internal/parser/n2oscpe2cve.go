package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"sort"
	"strings"
	"time"
)

// ParseN2OSCPE2CVELogs parses all n2os_cpe2cve.log files (including rotated logs)
func ParseN2OSCPE2CVELogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_cpe2cve.log", 5, parseN2OSCPE2CVELogFile)


	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSCPE2CVELogs = allEntries

	return nil
}

// parseN2OSCPE2CVELogFile parses a single n2os_cpe2cve.log file
func parseN2OSCPE2CVELogFile(path string) ([]models.N2OSCPE2CVELogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2os_cpe2cve.log", "cpe2cve")

	var entries []models.N2OSCPE2CVELogEntry
	scanner := bufio.NewScanner(file)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		lineNumber++

		// Format: 2026/04/14 02:22:53.930354 <message>
		ts, msg, ok := parseCPE2CVELine(line)
		if !ok {
			// No timestamp — continuation line, append to previous
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
				entries[len(entries)-1].Message += "\n" + line
			}
			continue
		}

		entries = append(entries, models.N2OSCPE2CVELogEntry{
			Timestamp:  ts,
			Message:    msg,
			Source:     source,
			LineNumber: lineNumber,
			RawLine:    line,
		})
	}

	return entries, scanner.Err()
}

// parseCPE2CVELine parses a cpe2cve log line.
// Format: 2026/04/14 02:22:53.930354 <message>
func parseCPE2CVELine(line string) (ts time.Time, msg string, ok bool) {
	// Minimum: "2026/04/14 02:22:53.930354 "
	if len(line) < 28 {
		return
	}
	tsStr := line[:26]
	t, err := time.Parse("2006/01/02 15:04:05.000000", tsStr)
	if err != nil {
		return
	}
	return t, strings.TrimSpace(line[26:]), true
}
