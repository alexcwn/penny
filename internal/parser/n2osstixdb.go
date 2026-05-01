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

// ParseN2OSStixDBLogs parses all n2os_stixdb.log files (including rotated logs)
func ParseN2OSStixDBLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_stixdb.log", 5, parseN2OSStixDBLogFile)


	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSStixDBLogs = allEntries

	return nil
}

func parseN2OSStixDBLogFile(path string) ([]models.N2OSStixDBLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2os_stixdb.log", "stixdb")

	var entries []models.N2OSStixDBLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// Format: 2025/03/27 06:23:28.528232 <message>
	lineRegex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(.*)`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		m := lineRegex.FindStringSubmatch(line)
		if len(m) > 2 {
			lineNumber++
			entry := models.N2OSStixDBLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
				Message:    strings.TrimSpace(m[2]),
			}
			if ts, err := parseStixDBTimestamp(m[1]); err == nil {
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

func parseStixDBTimestamp(ts string) (time.Time, error) {
	// Format: 2006/01/02 15:04:05.000000
	t, err := time.Parse("2006/01/02 15:04:05.000000", ts)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse("2006/01/02 15:04:05.000", ts)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse("2006/01/02 15:04:05", ts)
	if err == nil {
		return t, nil
	}
	return time.Time{}, err
}
