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

// ParseN2OSPumaLogs parses all puma.log files (including rotated logs)
func ParseN2OSPumaLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	allEntries := collectRotatedLogs(logDir, "puma.log", 5, parsePumaLogFile)

	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSPumaLogs = allEntries
	return nil
}

func parsePumaLogFile(path string) ([]models.N2OSPumaLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "puma.log", "puma")

	var entries []models.N2OSPumaLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// === puma startup: 2026-04-14 02:23:31 +0000 ===
	headerRegex := regexp.MustCompile(`^===\s+puma\s+\S+:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\s+===`)
	// [42519] - message  or  [42519] ! message
	pidLineRegex := regexp.MustCompile(`^\[(\d+)\]\s+([-!])\s+(.*)`)

	var currentTS time.Time
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Check for section header — update carried timestamp
		if hm := headerRegex.FindStringSubmatch(line); len(hm) > 1 {
			if ts, err := parsePumaTimestamp(hm[1]); err == nil {
				currentTS = ts
			}
			lineNumber++
			entries = append(entries, models.N2OSPumaLogEntry{
				Timestamp:  currentTS,
				Message:    strings.TrimSpace(line),
				Source:     source,
				LineNumber: lineNumber,
				RawLine:    line,
			})
			continue
		}

		lineNumber++
		entry := models.N2OSPumaLogEntry{
			Timestamp:  currentTS,
			Source:     source,
			LineNumber: lineNumber,
			RawLine:    line,
		}

		if pm := pidLineRegex.FindStringSubmatch(line); len(pm) > 3 {
			entry.PID = pm[1]
			if pm[2] == "!" {
				entry.Level = "WARN"
			} else {
				entry.Level = "INFO"
			}
			entry.Message = strings.TrimSpace(pm[3])
		} else {
			entry.Message = strings.TrimSpace(line)
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parsePumaTimestamp(ts string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05 -0700", ts)
}
