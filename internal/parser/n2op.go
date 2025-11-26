package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"penny/internal/validator"
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

	// Validate upgrade paths and collect violations
	data.UpgradeViolations = ValidateUpgradePaths(allEntries)

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
	heartbeatRegex := regexp.MustCompile(`n2os_ids\[(\d+)\]\[0x[0-9a-fA-F]+\] INFO: Nozomi Networks OS // (.+)`)

	// Upgrade patterns - handle multiple formats
	upgradeNewFormatRegex := regexp.MustCompile(`install_update executed successfully\. INFO: Nozomi Networks OS // (.+)`)
	upgradeOldFormatRegex := regexp.MustCompile(`install_update executed successfully\. N2OS version (.+)`)

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
			if len(matches) > 2 {
				entry.EventType = models.N2OpEventHeartbeat
				entry.PID = matches[1]
				entry.Version = matches[2]
			}

		case strings.Contains(line, "install_update: Starting N2OS upgrade process"):
			entry.EventType = models.N2OpEventUpgradeStart

		case upgradeNewFormatRegex.MatchString(line):
			// Upgrade complete - new format: "INFO: Nozomi Networks OS // VERSION"
			// VERSION can be either:
			//   - Just a version: "23.4.1-01081507_B028E"
			//   - From-to format: "from 23.3.1-11061610_311D6 to 23.4.1-01081507_B028E"
			matches := upgradeNewFormatRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				entry.EventType = models.N2OpEventUpgradeComplete
				versionInfo := strings.TrimSpace(matches[1])

				// Check if it's "from X to Y" format - flexible with whitespace
				fromToCheckRegex := regexp.MustCompile(`^from\s+.+?\s+to\s+`)
				if fromToCheckRegex.MatchString(versionInfo) {
					// For chained upgrades (X → Y → Z), extract only the last segment
					// This represents the most recent actual upgrade performed
					segments := strings.Split(versionInfo, " → ")
					lastSegment := strings.TrimSpace(segments[len(segments)-1])

					// Extract from and to versions from the last segment
					fromToRegex := regexp.MustCompile(`^from\s+(.+?)\s+to\s+(.+?)$`)
					fromToMatches := fromToRegex.FindStringSubmatch(lastSegment)
					if len(fromToMatches) > 2 {
						entry.FromVersion = strings.TrimSpace(fromToMatches[1])
						entry.ToVersion = strings.TrimSpace(fromToMatches[2])
					}
				} else {
					// Just a version string
					entry.ToVersion = versionInfo
				}
			}

		case upgradeOldFormatRegex.MatchString(line):
			// Upgrade complete - old format: "N2OS version X-X"
			matches := upgradeOldFormatRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				entry.EventType = models.N2OpEventUpgradeComplete
				entry.ToVersion = matches[1]
			}

		case strings.Contains(line, "/usr/local/sbin/n2os-start-all starting"):
			entry.EventType = models.N2OpEventSystemStart

		case strings.Contains(line, "/usr/local/sbin/n2os-start-all executed successfully"):
			entry.EventType = models.N2OpEventSystemStart
			entry.Message = line + " (completed)"

		case strings.Contains(line, "/usr/local/sbin/n2os-stop-all starting"):
			entry.EventType = models.N2OpEventSystemStop

		case strings.Contains(line, "/usr/local/sbin/n2os-stop-all executed successfully"):
			entry.EventType = models.N2OpEventSystemStop
			entry.Message = line + " (completed)"

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

	// Post-process: populate FromVersion for upgrade entries where it's empty
	// FromVersion is the ToVersion of the previous upgrade
	var lastUpgradeVersion string
	for i := range entries {
		if entries[i].EventType == models.N2OpEventUpgradeComplete {
			if entries[i].FromVersion == "" && lastUpgradeVersion != "" {
				entries[i].FromVersion = lastUpgradeVersion
			}
			// Update lastUpgradeVersion for next iteration
			if entries[i].ToVersion != "" {
				lastUpgradeVersion = entries[i].ToVersion
			}
		}
	}

	return entries, scanner.Err()
}

// parseN2OpTimestamp parses timestamps in multiple formats
// New format: 2022-03-10T07:29:23.128 +0100 (space before timezone, no colon)
// Old format: 2020-12-08T03:30:13+01:00 (no space, colon in timezone)
func parseN2OpTimestamp(ts string) (time.Time, error) {
	// Try new format with milliseconds and space before timezone
	t, err := time.Parse("2006-01-02T15:04:05.000 -0700", ts)
	if err == nil {
		return t, nil
	}

	// Try new format without milliseconds
	t, err = time.Parse("2006-01-02T15:04:05 -0700", ts)
	if err == nil {
		return t, nil
	}

	// Try old format with colon in timezone and milliseconds
	t, err = time.Parse("2006-01-02T15:04:05.000-07:00", ts)
	if err == nil {
		return t, nil
	}

	// Try old format with colon in timezone, no milliseconds
	t, err = time.Parse("2006-01-02T15:04:05-07:00", ts)
	if err == nil {
		return t, nil
	}

	return time.Time{}, err
}

// ValidateUpgradePaths validates all upgrade entries and returns violations
func ValidateUpgradePaths(entries []models.N2OpLogEntry) []models.UpgradeViolation {
	var violations []models.UpgradeViolation

	for _, entry := range entries {
		// Only validate upgrade_complete events with both FromVersion and ToVersion
		if entry.EventType != models.N2OpEventUpgradeComplete {
			continue
		}

		// Skip entries without proper version data
		if entry.FromVersion == "" || entry.ToVersion == "" {
			continue
		}

		// Validate the upgrade path
		errMsg := validator.ValidateUpgradePath(entry.FromVersion, entry.ToVersion)
		if errMsg != "" {
			violations = append(violations, models.UpgradeViolation{
				Timestamp:   entry.Timestamp,
				FromVersion: entry.FromVersion,
				ToVersion:   entry.ToVersion,
				Description: errMsg,
				DocsURL:     validator.GetDocsURL(entry.ToVersion),
			})
		}
	}

	return violations
}
