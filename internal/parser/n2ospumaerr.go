package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ParseN2OSPumaErrLogs parses all puma-err.log files (including rotated logs)
func ParseN2OSPumaErrLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	var allEntries []models.N2OSPumaErrLogEntry

	for i := 5; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("puma-err.log.%d", i))
		if entries, err := parsePumaErrLogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	currentLogPath := filepath.Join(logDir, "puma-err.log")
	if entries, err := parsePumaErrLogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OSPumaErrLogs = allEntries
	return nil
}

func parsePumaErrLogFile(path string) ([]models.N2OSPumaErrLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractLogSource(filename, "puma-err.log", "puma-err")

	var entries []models.N2OSPumaErrLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	headerRegex := regexp.MustCompile(`^===\s+puma\s+\S+:\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})\s+===`)

	var currentTS time.Time
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if hm := headerRegex.FindStringSubmatch(line); len(hm) > 1 {
			if ts, err := parsePumaErrTimestamp(hm[1]); err == nil {
				currentTS = ts
			}
		}

		lineNumber++
		entries = append(entries, models.N2OSPumaErrLogEntry{
			Timestamp:  currentTS,
			Message:    strings.TrimSpace(line),
			Source:     source,
			LineNumber: lineNumber,
			RawLine:    line,
		})
	}

	return entries, scanner.Err()
}

func parsePumaErrTimestamp(ts string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05 -0700", ts)
}
