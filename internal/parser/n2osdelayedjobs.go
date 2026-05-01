package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strconv"
)

// ParseN2OSDelayedJobLogs parses n2osdelayedjobs.log (no rotation)
func ParseN2OSDelayedJobLogs(baseDir string, data *models.ArchiveData) error {
	logPath := filepath.Join(resolveN2OSLogDir(baseDir), "n2osdelayedjobs.log")
	entries, err := parseN2OSDelayedJobLogFile(logPath)
	if err != nil {
		return err
	}
	data.N2OSJobDelayedLogs = entries
	return nil
}

func parseN2OSDelayedJobLogFile(path string) ([]models.N2OSJobDelayedLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.N2OSJobDelayedLogEntry
	scanner := bufio.NewScanner(file)

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
			entry := models.N2OSJobDelayedLogEntry{
				RawLine:    line,
				Source:     "delayed_jobs",
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
			entry := models.N2OSJobDelayedLogEntry{
				RawLine:    line,
				Source:     "delayed_jobs",
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
