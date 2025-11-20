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

// ParseN2OpLogs parses all n2op.log files (including rotated logs)
func ParseN2OpLogs(baseDir string, data *models.ArchiveData) error {
	logDir := filepath.Join(baseDir, "data", "log", "n2os")

	var allEntries []models.N2OpLogEntry

	// Parse rotated logs in reverse order (oldest first: n2op.log.6 -> n2op.log.0)
	for i := 6; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("n2op.log.%d", i))
		if entries, err := parseN2OpLogFile(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current log last (newest)
	currentLogPath := filepath.Join(logDir, "n2op.log")
	if entries, err := parseN2OpLogFile(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	data.N2OpLogs = allEntries
	return nil
}

// parseN2OpLogFile parses a single n2op.log file
func parseN2OpLogFile(path string) ([]models.N2OpLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.N2OpLogEntry
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing
	timestampRegex := regexp.MustCompile(`^\[([^\]]+)\]`)
	heartbeatRegex := regexp.MustCompile(`n2os_ids\[(\d+)\]\[(\d+)\] INFO: Nozomi Networks OS // (.+)`)
	upgradeCompleteRegex := regexp.MustCompile(`install_update executed successfully\. INFO: Nozomi Networks OS // from (.+) to (.+)`)
	serviceStopRegex := regexp.MustCompile(`^(.+) stop$`)
	serviceStartRegex := regexp.MustCompile(`^(.+) start$`)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := models.N2OpLogEntry{
			RawLine: line,
		}

		// Parse timestamp
		timestampMatch := timestampRegex.FindStringSubmatch(line)
		if len(timestampMatch) > 1 {
			if ts, err := parseN2OpTimestamp(timestampMatch[1]); err == nil {
				entry.Timestamp = ts
			}
			// Remove timestamp from message
			line = strings.TrimSpace(timestampRegex.ReplaceAllString(line, ""))
		}

		entry.Message = line

		// Classify event type and extract relevant fields
		switch {
		case heartbeatRegex.MatchString(line):
			// Heartbeat log
			matches := heartbeatRegex.FindStringSubmatch(line)
			if len(matches) > 3 {
				entry.EventType = models.N2OpEventHeartbeat
				entry.PID = matches[1]
				entry.ThreadID = matches[2]
				entry.Version = matches[3]
			}

		case strings.Contains(line, "install_update: Starting N2OS upgrade process"):
			entry.EventType = models.N2OpEventUpgradeStart

		case upgradeCompleteRegex.MatchString(line):
			// Upgrade complete
			matches := upgradeCompleteRegex.FindStringSubmatch(line)
			if len(matches) > 2 {
				entry.EventType = models.N2OpEventUpgradeComplete
				entry.FromVersion = matches[1]
				entry.ToVersion = matches[2]
			}

		case strings.Contains(line, "/usr/local/sbin/n2os-start-all starting"):
			entry.EventType = models.N2OpEventSystemStart

		case strings.Contains(line, "/usr/local/sbin/n2os-stop-all starting"):
			entry.EventType = models.N2OpEventSystemStop

		case serviceStopRegex.MatchString(line):
			// Service stop
			matches := serviceStopRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				entry.EventType = models.N2OpEventServiceStop
				entry.Service = matches[1]
			}

		case serviceStartRegex.MatchString(line):
			// Service start
			matches := serviceStartRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				entry.EventType = models.N2OpEventServiceStart
				entry.Service = matches[1]
			}

		default:
			entry.EventType = models.N2OpEventOther
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// parseN2OpTimestamp parses timestamps in format: 2025-02-15T10:10:23.413 +0800
func parseN2OpTimestamp(ts string) (time.Time, error) {
	// Try with milliseconds
	t, err := time.Parse("2006-01-02T15:04:05.000 -0700", ts)
	if err == nil {
		return t, nil
	}

	// Try without milliseconds
	t, err = time.Parse("2006-01-02T15:04:05 -0700", ts)
	if err == nil {
		return t, nil
	}

	return time.Time{}, err
}
