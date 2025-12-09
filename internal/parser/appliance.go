package parser

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"penny/internal/models"
)

// ParseAppliances parses appliance.csv from health_check directory
func ParseAppliances(baseDir string, data *models.ArchiveData) error {
	appliancePath := filepath.Join(baseDir, "health_check", "appliance.csv")

	file, err := os.Open(appliancePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, not an error
		}
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Build column index map
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[strings.TrimSpace(col)] = i
	}

	var appliances []models.Appliance

	// Read records
	for {
		record, err := reader.Read()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("failed to read CSV record: %w", err)
		}

		if len(record) == 0 {
			continue
		}

		appliance := parseApplianceRecord(record, colIndex)
		if appliance != nil {
			appliances = append(appliances, *appliance)
		}
	}

	data.Appliances = appliances
	return nil
}

func parseApplianceRecord(record []string, colIndex map[string]int) *models.Appliance {
	a := &models.Appliance{}

	// Helper function to safely get column value
	getCol := func(name string) string {
		if idx, ok := colIndex[name]; ok && idx < len(record) {
			return strings.TrimSpace(record[idx])
		}
		return ""
	}

	// Simple fields (strings)
	a.IP = getCol("ip")
	a.ID = getCol("id")
	a.Info = getCol("info")
	a.MapPosition = getCol("map_position")
	a.Site = getCol("site")
	a.Host = getCol("host")
	a.Health = getCol("health")
	a.ApplianceID = getCol("appliance_id")
	a.ApplianceIP = getCol("appliance_ip")
	a.ApplianceHost = getCol("appliance_host")
	a.Model = getCol("model")
	a.LastSeenPacket = getCol("last_seen_packet")

	// Boolean fields (parse 't'/'f' or 'true'/'false')
	a.Allowed = parseBool(getCol("allowed"))
	a.IsUpdating = parseBool(getCol("is_updating"))
	a.Synchronized = parseBool(getCol("synchronized"))
	a.Replicated = parseBool(getCol("replicated"))
	a.ForceUpdate = parseBool(getCol("force_update"))

	// Numeric fields
	a.SyncThroughput = parseInt64(getCol("sync_throughput"))
	a.DeletedAt = parseInt64(getCol("deleted_at"))

	// Timestamp fields (Unix milliseconds)
	if ts, err := parseUnixMillis(getCol("last_sync")); err == nil {
		a.LastSync = ts
	}
	if ts, err := parseUnixMillis(getCol("time")); err == nil {
		a.Time = ts
	}

	return a
}

func parseInt64(val string) int64 {
	if val == "" {
		return 0
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
