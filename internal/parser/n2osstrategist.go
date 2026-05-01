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

// ParseN2OSStrategistLogs parses all n2os_strategist.log files (including rotated logs)
func ParseN2OSStrategistLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "n2os_strategist.log", 5, parseN2OSStrategistLogFile)


	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSStrategistLogs = allEntries

	return nil
}

func parseN2OSStrategistLogFile(path string) ([]models.N2OSStrategistLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "n2os_strategist.log", "strategist")

	var entries []models.N2OSStrategistLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// Format variant A: 2025-04-01 10:05:39 | Info | SmartPolling | message (4 fields)
	// Format variant B: 2026-04-14 02:23:35 | Info | message             (3 fields)
	lineRegex4 := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*(\w+)\s*\|\s*([^|]+?)\s*\|\s*(.+)`)
	lineRegex3 := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*(\w+)\s*\|\s*(.+)`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var matched bool
		if m := lineRegex4.FindStringSubmatch(line); len(m) > 4 {
			lineNumber++
			entry := models.N2OSStrategistLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
				Level:      strings.TrimSpace(m[2]),
				Component:  strings.TrimSpace(m[3]),
				Message:    strings.TrimSpace(m[4]),
			}
			if ts, err := parseStrategistTimestamp(m[1]); err == nil {
				entry.Timestamp = ts
			}
			entries = append(entries, entry)
			matched = true
		} else if m := lineRegex3.FindStringSubmatch(line); len(m) > 3 {
			lineNumber++
			entry := models.N2OSStrategistLogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
				Level:      strings.TrimSpace(m[2]),
				Message:    strings.TrimSpace(m[3]),
			}
			if ts, err := parseStrategistTimestamp(m[1]); err == nil {
				entry.Timestamp = ts
			}
			entries = append(entries, entry)
			matched = true
		}
		if !matched {
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
				entries[len(entries)-1].Message += "\n" + line
			}
		}
	}

	return entries, scanner.Err()
}

func parseStrategistTimestamp(ts string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05", ts)
}
