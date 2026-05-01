package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ParseN2OSSpLogs parses all n2ossp.log files (including rotated logs)
func ParseN2OSSpLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2ossp.log", 5, parseN2OSSpLogFile)


	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSSpLogs = allEntries
	return nil
}

func parseN2OSSpLogFile(path string) ([]models.N2OSSpLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2ossp.log", "sp")

	var entries []models.N2OSSpLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// Ruby logger format: X, [2026-04-20T18:27:25+00:00  #99924] LEVEL -- : message
	lineRegex := regexp.MustCompile(`^([A-Z]),\s+\[([^\]]+)\]\s+(\w+)\s+--\s+:\s+(.*)`)

	// Map short Ruby logger codes to full level names
	levelMap := map[string]string{
		"D": "DEBUG", "I": "INFO", "W": "WARN",
		"E": "ERROR", "F": "FATAL", "A": "ANY",
	}

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		m := lineRegex.FindStringSubmatch(line)
		if len(m) > 4 {
			lineNumber++
			level := levelMap[m[1]]
			if level == "" {
				level = m[3]
			}
			entry := models.N2OSSpLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
				Level:      level,
				PID:        extractSpPID(m[2]),
				Message:    strings.TrimSpace(m[4]),
			}
			if ts, err := parseSpTimestamp(m[2]); err == nil {
				entry.Timestamp = ts
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

// extractSpPID pulls the #PID out of the bracket field e.g. "2026-04-20T18:27:25+00:00  #99924"
func extractSpPID(bracket string) string {
	pidRegex := regexp.MustCompile(`#(\d+)`)
	m := pidRegex.FindStringSubmatch(bracket)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func parseSpTimestamp(bracket string) (time.Time, error) {
	// bracket looks like "2026-04-20T18:27:25+00:00  #99924" — strip PID suffix
	ts := strings.TrimSpace(regexp.MustCompile(`\s+#\d+$`).ReplaceAllString(bracket, ""))
	t, err := time.Parse("2006-01-02T15:04:05-07:00", ts)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse("2006-01-02T15:04:05+00:00", ts)
	if err == nil {
		return t, nil
	}
	return time.Time{}, err
}
