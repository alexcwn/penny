package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"penny/internal/models"
)

// ParseN2OSAlertLogs parses both n2os_alert.log* and n2os_alert_events.log* files
func ParseN2OSAlertLogs(baseDir string, data *models.ArchiveData) error {
	logDir := resolveN2OSLogDir(baseDir)

	var alertEntries []models.N2OSAlertLogEntry
	var eventsEntries []models.N2OSAlertEventsLogEntry

	// Parse rotated alert logs oldest first
	for i := 5; i >= 0; i-- {
		path := filepath.Join(logDir, fmt.Sprintf("n2os_alert.log.%d", i))
		source := fmt.Sprintf("alert.%d", i)
		if entries, err := readN2OSAlertLogFile(path, source); err == nil {
			alertEntries = append(alertEntries, entries...)
		}
	}
	if entries, err := readN2OSAlertLogFile(filepath.Join(logDir, "n2os_alert.log"), "alert"); err == nil {
		alertEntries = append(alertEntries, entries...)
	}

	// Parse rotated alert events logs oldest first
	for i := 5; i >= 0; i-- {
		path := filepath.Join(logDir, fmt.Sprintf("n2os_alert_events.log.%d", i))
		source := fmt.Sprintf("alert_events.%d", i)
		if entries, err := readN2OSAlertEventsLogFile(path, source); err == nil {
			eventsEntries = append(eventsEntries, entries...)
		}
	}
	if entries, err := readN2OSAlertEventsLogFile(filepath.Join(logDir, "n2os_alert_events.log"), "alert_events"); err == nil {
		eventsEntries = append(eventsEntries, entries...)
	}

	sort.Slice(alertEntries, func(i, j int) bool {
		return alertEntries[i].Timestamp.Before(alertEntries[j].Timestamp)
	})
	sort.Slice(eventsEntries, func(i, j int) bool {
		return eventsEntries[i].Timestamp.Before(eventsEntries[j].Timestamp)
	})

	data.N2OSAlertLogs = alertEntries
	data.N2OSAlertEventsLogs = eventsEntries
	return nil
}

func readN2OSAlertLogFile(path, source string) ([]models.N2OSAlertLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.N2OSAlertLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	alertLogRegex := regexp.MustCompile(`^\[([^\]]+)\]\s+n2os_alert\[(\d+)\]\[(\d+)\]\s+([A-Z_]+):\s*(.*)`)

	var currentEntry *models.N2OSAlertLogEntry
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		matches := alertLogRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			if currentEntry != nil {
				entries = append(entries, *currentEntry)
			}
			currentEntry = &models.N2OSAlertLogEntry{
				Timestamp:  parseN2OSAlertTimestamp(matches[1]),
				ProcessID:  matches[2],
				ThreadID:   matches[3],
				Level:      matches[4],
				Message:    matches[5],
				Source:     source,
				LineNumber: lineNumber,
				RawLine:    line,
			}
		} else if currentEntry != nil && strings.TrimSpace(line) != "" {
			currentEntry.Message += "\n" + line
			currentEntry.RawLine += "\n" + line
		}
	}
	if currentEntry != nil {
		entries = append(entries, *currentEntry)
	}
	return entries, scanner.Err()
}

func readN2OSAlertEventsLogFile(path, source string) ([]models.N2OSAlertEventsLogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.N2OSAlertEventsLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	eventLogRegex := regexp.MustCompile(`^\[([^\]]+)\]\s+n2os_alert\[(\d+)\]\[(\d+)\]\s+EVENT:\s*(.*)`)

	var currentEntry *models.N2OSAlertEventsLogEntry
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		matches := eventLogRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			if currentEntry != nil {
				entries = append(entries, *currentEntry)
			}
			eventData := matches[4]
			currentEntry = &models.N2OSAlertEventsLogEntry{
				Timestamp:  parseN2OSAlertTimestamp(matches[1]),
				ProcessID:  matches[2],
				ThreadID:   matches[3],
				EventType:  extractAlertEventType(eventData),
				Event:      eventData,
				Source:     source,
				LineNumber: lineNumber,
				RawLine:    line,
			}
		} else if currentEntry != nil && strings.TrimSpace(line) != "" {
			currentEntry.Event += "\n" + line
			currentEntry.RawLine += "\n" + line
		}
	}
	if currentEntry != nil {
		entries = append(entries, *currentEntry)
	}
	return entries, scanner.Err()
}

// parseN2OSAlertTimestamp parses timestamp from alert log format
// Format: 2024-08-28T14:42:16.523 +0000
func parseN2OSAlertTimestamp(timestampStr string) time.Time {
	// Try to parse with timezone offset first to preserve timezone information
	formats := []string{
		"2006-01-02T15:04:05.000 -0700", // With timezone
		"2006-01-02T15:04:05 -0700",      // With timezone, no milliseconds
		"2006-01-02T15:04:05.000",        // Without timezone
		"2006-01-02T15:04:05",            // Without timezone, no milliseconds
		"2006-01-02 15:04:05.000 -0700",  // Space-separated with timezone
		"2006-01-02 15:04:05 -0700",      // Space-separated with timezone, no milliseconds
		"2006-01-02 15:04:05.000",        // Space-separated without timezone
		"2006-01-02 15:04:05",            // Space-separated without timezone, no milliseconds
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timestampStr); err == nil {
			return t
		}
	}

	// Fallback to current time if parse fails
	return time.Now()
}

// extractAlertEventType extracts the event type from alert event data
// Handles both legacy format: "Contents{ ... }" and modern format: {"Contents":{...}, "type":"stop"}
func extractAlertEventType(eventData string) string {
	eventData = strings.TrimSpace(eventData)

	// Try to extract "type" field from JSON (modern format)
	if strings.HasPrefix(eventData, "{") {
		// Look for "type" field
		typeRegex := regexp.MustCompile(`"type"\s*:\s*"([^"]+)"`)
		matches := typeRegex.FindStringSubmatch(eventData)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// Check for legacy format: "Contents{ ... }"
	if strings.HasPrefix(eventData, "Contents{") {
		return "metrics"
	}

	// Default to "event"
	return "event"
}

// Helper function to convert PID/ThreadID strings if needed
func parseProcID(idStr string) string {
	// Validate it's a number
	if _, err := strconv.ParseInt(idStr, 10, 64); err == nil {
		return idStr
	}
	return idStr
}
