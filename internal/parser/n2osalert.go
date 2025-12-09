package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"penny/internal/models"
)

// ParseN2OSAlertLogs parses both n2os_alert.log and n2os_alert_events.log files
func ParseN2OSAlertLogs(baseDir string, data *models.ArchiveData) error {
	// Parse main alert logs
	if err := parseN2OSAlertLogFile(baseDir, data); err != nil {
		// Non-fatal error
	}

	// Parse alert events logs
	if err := parseN2OSAlertEventsLogFile(baseDir, data); err != nil {
		// Non-fatal error
	}

	return nil
}

// parseN2OSAlertLogFile parses n2os_alert.log
func parseN2OSAlertLogFile(baseDir string, data *models.ArchiveData) error {
	alertPath := filepath.Join(baseDir, "data", "log", "n2os", "n2os_alert.log")

	file, err := os.Open(alertPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, not an error
		}
		return err
	}
	defer file.Close()

	var entries []models.N2OSAlertLogEntry
	scanner := bufio.NewScanner(file)

	// Regex pattern for alert log lines
	// Format: [TIMESTAMP] n2os_alert[PID][ThreadID] LEVEL: Message
	alertLogRegex := regexp.MustCompile(`^\[([^\]]+)\]\s+n2os_alert\[(\d+)\]\[(\d+)\]\s+([A-Z_]+):\s*(.*)`)

	var currentEntry *models.N2OSAlertLogEntry
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		// Try to match alert log pattern
		matches := alertLogRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Save previous entry
			if currentEntry != nil {
				entries = append(entries, *currentEntry)
			}

			// Create new entry
			timestamp := parseN2OSAlertTimestamp(matches[1])
			currentEntry = &models.N2OSAlertLogEntry{
				Timestamp:  timestamp,
				ProcessID:  matches[2],
				ThreadID:   matches[3],
				Level:      matches[4],
				Message:    matches[5],
				Source:     "alert",
				LineNumber: lineNumber,
				RawLine:    line,
			}
		} else if currentEntry != nil && strings.TrimSpace(line) != "" {
			// Continue previous message (multi-line)
			currentEntry.Message += "\n" + line
			currentEntry.RawLine += "\n" + line
		}
	}

	// Save last entry
	if currentEntry != nil {
		entries = append(entries, *currentEntry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning alert log: %w", err)
	}

	data.N2OSAlertLogs = entries
	return nil
}

// parseN2OSAlertEventsLogFile parses n2os_alert_events.log
func parseN2OSAlertEventsLogFile(baseDir string, data *models.ArchiveData) error {
	eventsPath := filepath.Join(baseDir, "data", "log", "n2os", "n2os_alert_events.log")

	file, err := os.Open(eventsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, not an error
		}
		return err
	}
	defer file.Close()

	var entries []models.N2OSAlertEventsLogEntry
	scanner := bufio.NewScanner(file)

	// Regex pattern for alert events log lines
	// Format: [TIMESTAMP] n2os_alert[PID][ThreadID] EVENT: {JSON_DATA}
	eventLogRegex := regexp.MustCompile(`^\[([^\]]+)\]\s+n2os_alert\[(\d+)\]\[(\d+)\]\s+EVENT:\s*(.*)`)

	var currentEntry *models.N2OSAlertEventsLogEntry
	lineNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		// Try to match event log pattern
		matches := eventLogRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Save previous entry
			if currentEntry != nil {
				entries = append(entries, *currentEntry)
			}

			// Create new entry
			timestamp := parseN2OSAlertTimestamp(matches[1])
			eventData := matches[4]
			eventType := extractAlertEventType(eventData)

			currentEntry = &models.N2OSAlertEventsLogEntry{
				Timestamp:  timestamp,
				ProcessID:  matches[2],
				ThreadID:   matches[3],
				EventType:  eventType,
				Event:      eventData,
				Source:     "alert_events",
				LineNumber: lineNumber,
				RawLine:    line,
			}
		} else if currentEntry != nil && strings.TrimSpace(line) != "" {
			// Continue previous event (multi-line JSON)
			currentEntry.Event += "\n" + line
			currentEntry.RawLine += "\n" + line
		}
	}

	// Save last entry
	if currentEntry != nil {
		entries = append(entries, *currentEntry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning alert events log: %w", err)
	}

	data.N2OSAlertEventsLogs = entries
	return nil
}

// parseN2OSAlertTimestamp parses timestamp from alert log format
// Format: 2024-08-28T14:42:16.523 +0000
func parseN2OSAlertTimestamp(timestampStr string) time.Time {
	// Remove timezone suffix if present
	parts := strings.Fields(timestampStr)
	if len(parts) > 0 {
		timestampStr = parts[0]
	}

	// Try to parse ISO format with milliseconds
	formats := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
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
