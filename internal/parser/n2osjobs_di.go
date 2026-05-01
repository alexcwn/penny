package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ParseN2OSJobDILogs parses all n2osjobs_di.log files (including rotated logs)
func ParseN2OSJobDILogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	var allEntries []models.N2OSJobDILogEntry

	// Parse rotated logs in reverse order (oldest first: n2osjobs_di.log.0 is the only rotation)
	for i := 4; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("n2osjobs_di.log.%d", i))
		if entries, err := parseN2OSJobDILogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "n2osjobs_di.log")
	if entries, err := parseN2OSJobDILogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp, then source, then line number for stable chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		if !allEntries[i].Timestamp.Equal(allEntries[j].Timestamp) {
			return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
		}
		if allEntries[i].Source != allEntries[j].Source {
			return compareJobDISources(allEntries[i].Source, allEntries[j].Source)
		}
		return allEntries[i].LineNumber < allEntries[j].LineNumber
	})

	data.N2OSJobDILogs = allEntries

	return nil
}

// compareJobDISources returns true if sourceA should come before sourceB
// Order: jobs_di.4 < jobs_di.3 < ... < jobs_di.0 < jobs_di
func compareJobDISources(sourceA, sourceB string) bool {
	extractNum := func(s string) int {
		if s == "jobs_di" {
			return -1
		}
		parts := strings.Split(s, ".")
		if len(parts) == 2 {
			if num, err := strconv.Atoi(parts[1]); err == nil {
				return num
			}
		}
		return -1
	}
	return extractNum(sourceA) > extractNum(sourceB)
}

// parseN2OSJobDILogFile parses a single n2osjobs_di.log file
func parseN2OSJobDILogFile(path string) ([]models.N2OSJobDILogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	filename := filepath.Base(path)
	source := extractJobDISourceFromFilename(filename)

	var entries []models.N2OSJobDILogEntry
	scanner := bufio.NewScanner(file)

	// Same Ruby logger format as n2osjobs.log
	// Example: I, [2026-04-21T05:21:57+00:00  #62738]  INFO -- : cef(udp://...)(alerts): progress 0 ...
	timestampRegex := regexp.MustCompile(`^[A-Z], \[([^\]]+)\]`)
	headerRegex := regexp.MustCompile(`^# Logfile created on (.+?) by`)
	executedRegex := regexp.MustCompile(`(IDSApi::[A-Za-z:]+Task) executed in ([\d.]+)ms`)

	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		headerMatch := headerRegex.FindStringSubmatch(line)
		if len(headerMatch) > 1 {
			lineNumber++
			entry := models.N2OSJobDILogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}
			if ts, err := parseLogHeaderTimestamp(headerMatch[1]); err == nil {
				entry.Timestamp = ts
			}
			entries = append(entries, entry)
			continue
		}

		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			lineNumber++
			entry := models.N2OSJobDILogEntry{
				RawLine:    line,
				Source:     source,
				LineNumber: lineNumber,
			}
			if ts, err := parseN2OSJobTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}
			executedMatch := executedRegex.FindStringSubmatch(line)
			if len(executedMatch) > 2 {
				entry.TaskName = executedMatch[1]
				if duration, err := strconv.ParseFloat(executedMatch[2], 64); err == nil {
					entry.DurationMS = duration
				}
			}
			entries = append(entries, entry)
		} else {
			if len(entries) > 0 {
				entries[len(entries)-1].RawLine += "\n" + line
			}
		}
	}

	return entries, scanner.Err()
}

// extractJobDISourceFromFilename converts a log filename to its source identifier
// "n2osjobs_di.log" -> "jobs_di"
// "n2osjobs_di.log.0" -> "jobs_di.0"
func extractJobDISourceFromFilename(filename string) string {
	if filename == "n2osjobs_di.log" {
		return "jobs_di"
	}
	if strings.HasPrefix(filename, "n2osjobs_di.log.") {
		suffix := strings.TrimPrefix(filename, "n2osjobs_di.log.")
		return "jobs_di." + suffix
	}
	return "jobs_di"
}
