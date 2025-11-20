package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"strconv"
	"strings"
	"time"
)

// ParseHealthLogs parses health_check/health_logs.csv
func ParseHealthLogs(baseDir string, data *models.ArchiveData) error {
	healthLogsPath := filepath.Join(baseDir, "health_check", "health_logs.csv")

	file, err := os.Open(healthLogsPath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Check if this is an 8-column or 9-column format
	// 8-column: id,time,appliance_id,appliance_ip,appliance_host,synchronized,info,replicated
	// 9-column: id,time,appliance_id,appliance_ip,appliance_host,synchronized,info,replicated,record_created_at
	hasRecordCreatedAt := len(header) == 9
	if len(header) != 8 && len(header) != 9 {
		return fmt.Errorf("unexpected CSV header format: expected 8 or 9 columns, got %d", len(header))
	}

	var events []models.HealthEvent

	// Read all records
	for {
		record, err := reader.Read()
		if err != nil {
			break // EOF or error
		}

		// Skip malformed rows - must match header column count
		if len(record) != len(header) {
			continue
		}

		event := models.HealthEvent{
			ID:            record[0],
			ApplianceID:   record[2],
			ApplianceIP:   record[3],
			ApplianceHost: record[4],
			Synchronized:  parseBool(record[5]),
			InfoJSON:      record[6],
			Replicated:    parseBool(record[7]),
		}

		// Parse timestamps (milliseconds since epoch)
		if timestamp, err := parseUnixMillis(record[1]); err == nil {
			event.Timestamp = timestamp
		}

		// Parse record_created_at if column exists (9-column format)
		if hasRecordCreatedAt && len(record) > 8 {
			if recordCreated, err := parseUnixMillis(record[8]); err == nil {
				event.RecordCreatedAt = recordCreated
			}
		}

		// Parse info JSON
		parseInfoJSON(&event)

		// Classify event type and category
		classifyHealthEvent(&event)

		events = append(events, event)
	}

	data.HealthEvents = events
	return nil
}

// parseInfoJSON parses the JSON info field and extracts relevant data
func parseInfoJSON(event *models.HealthEvent) {
	if event.InfoJSON == "" {
		return
	}

	var info map[string]interface{}
	if err := json.Unmarshal([]byte(event.InfoJSON), &info); err != nil {
		// If JSON parsing fails, just use the raw string
		event.Description = event.InfoJSON
		return
	}

	// Extract common fields
	if desc, ok := info["description"].(string); ok {
		event.Description = desc
	}

	// Extract is_stale field (can be true, false, or absent)
	if isStale, ok := info["is_stale"].(bool); ok {
		event.IsStale = &isStale
	}

	// Store any other relevant fields for future use
	// This allows forward compatibility with new fields
}

// classifyHealthEvent determines the category, type, and severity of a health event
func classifyHealthEvent(event *models.HealthEvent) {
	desc := strings.ToLower(event.Description)

	// Classify by description patterns
	switch {
	// Link events
	case strings.Contains(desc, "link_up"):
		event.Category = models.HealthCategoryNetwork
		event.EventType = models.HealthEventLinkUp
		event.Severity = models.HealthSeverityInfo
		event.Port = extractPort(desc)

	case strings.Contains(desc, "link_down"):
		event.Category = models.HealthCategoryNetwork
		event.EventType = models.HealthEventLinkDown
		event.Severity = models.HealthSeverityWarning
		event.Port = extractPort(desc)

	// Appliance stale events
	case event.IsStale != nil && *event.IsStale:
		event.Category = models.HealthCategoryAppliance
		event.EventType = models.HealthEventApplianceStale
		event.Severity = models.HealthSeverityWarning

	case event.IsStale != nil && !*event.IsStale:
		event.Category = models.HealthCategoryAppliance
		event.EventType = models.HealthEventApplianceRecovered
		event.Severity = models.HealthSeverityInfo

	// Last seen packet events
	case strings.Contains(desc, "last seen packet"):
		event.Category = models.HealthCategoryAppliance
		event.EventType = models.HealthEventLastSeenPacket
		event.Severity = models.HealthSeverityInfo
		event.LastSeenPacket = extractLastSeenTime(desc)

	// Recommended changes (upgrade-related)
	case strings.Contains(desc, "recommended changes"):
		event.Category = models.HealthCategoryUpgrade
		event.EventType = models.HealthEventRecommendedChanges
		event.Severity = models.HealthSeverityInfo
		event.VersionInfo = extractVersionInfo(desc)

	// Replication issues (based on synchronized/replicated flags)
	case !event.Synchronized || !event.Replicated:
		event.Category = models.HealthCategoryReplication
		event.EventType = models.HealthEventReplicationIssue
		event.Severity = models.HealthSeverityWarning

	// Default classification
	default:
		event.Category = models.HealthCategoryOther
		event.EventType = models.HealthEventOther
		event.Severity = models.HealthSeverityInfo
	}
}

// extractPort extracts port name from descriptions like "LINK_UP_on_port_mgmt"
func extractPort(desc string) string {
	// Look for pattern: on_port_XXX or on_port_portX
	if idx := strings.Index(desc, "on_port_"); idx != -1 {
		portPart := desc[idx+8:] // Skip "on_port_"
		// Take until end or whitespace
		if spaceIdx := strings.IndexAny(portPart, " \n\t"); spaceIdx != -1 {
			return portPart[:spaceIdx]
		}
		return portPart
	}
	return ""
}

// extractLastSeenTime extracts timestamp from "last seen packet: YYYY-MM-DD HH:MM:SS +ZZZZ"
func extractLastSeenTime(desc string) string {
	if idx := strings.Index(desc, "last seen packet:"); idx != -1 {
		timeStr := strings.TrimSpace(desc[idx+17:])
		return timeStr
	}
	return ""
}

// extractVersionInfo extracts version information from upgrade descriptions
func extractVersionInfo(desc string) string {
	// Look for version patterns like "22.5.0"
	lines := strings.Split(desc, "\n")
	for _, line := range lines {
		if strings.Contains(line, "version") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// parseUnixMillis converts Unix millisecond timestamp to time.Time
func parseUnixMillis(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	millis, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	seconds := millis / 1000
	nanos := (millis % 1000) * 1000000
	return time.Unix(seconds, nanos), nil
}

// parseBool converts 't'/'f' or 'true'/'false' to bool
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "t" || s == "true"
}
