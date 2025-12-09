package parser

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"penny/internal/models"
)

// ParseN2OSConf parses the n2os.conf.gz file
func ParseN2OSConf(baseDir string, data *models.ArchiveData) error {
	confPath := filepath.Join(baseDir, "data", "cfg", "n2os.conf.gz")

	// Open gzip file
	file, err := os.Open(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, not an error
		}
		return err
	}
	defer file.Close()

	// Decompress gzip
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	// Read raw content for storage
	rawContent := strings.Builder{}
	scanner := bufio.NewScanner(gzipReader)

	var entries []models.N2OSConfEntry
	addressCount := make(map[string]int)
	uuidSet := make(map[string]bool)
	commandCounts := make(map[string]int)
	var timestamp int64
	lineNumber := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNumber++
		rawContent.WriteString(line + "\n")

		// Parse timestamp from first line if present
		if lineNumber == 1 && strings.HasPrefix(line, "# timestamp") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if ts, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
					timestamp = ts
				}
			}
			continue
		}

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse entry
		entry := parseN2OSConfLine(line, lineNumber)
		if entry != nil {
			entries = append(entries, *entry)
			addressCount[entry.Address]++
			commandCounts[entry.CommandType]++
			if entry.UUID != "" {
				uuidSet[entry.UUID] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning file: %w", err)
	}

	// Calculate top addresses
	topAddresses := calculateTopAddresses(addressCount, 20)

	// Build stats
	stats := models.N2OSConfStats{
		TotalLines:      lineNumber,
		Timestamp:       timestamp,
		CommandCounts:   commandCounts,
		TopAddresses:    topAddresses,
		UniqueAddresses: len(addressCount),
		UniqueUUIDs:     len(uuidSet),
	}

	// Store result
	data.N2OSConfData = models.N2OSConfData{
		RawContent: rawContent.String(),
		Entries:    entries,
		Stats:      stats,
	}

	// Extract timezone from n2os.conf.user
	extractTimezoneFromConf(baseDir, data)

	return nil
}

// parseN2OSConfLine parses a single configuration line
func parseN2OSConfLine(line string, lineNumber int) *models.N2OSConfEntry {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	// Only process "vi" commands
	if parts[0] != "vi" {
		return nil
	}

	entry := &models.N2OSConfEntry{
		LineNumber: lineNumber,
	}

	// Check for "vi network_map compatibility" command
	if len(parts) >= 4 && parts[1] == "network_map" && parts[2] == "compatibility" {
		entry.CommandType = "network_map"
		entry.Address = parts[3]
		if len(parts) >= 5 {
			entry.UUID = parts[4]
		}
		// Remaining params
		if len(parts) > 5 {
			entry.Params = strings.Join(parts[5:], " ")
		}
		return entry
	}

	// Check for "vi link" command
	if len(parts) >= 3 && parts[1] == "link" {
		entry.CommandType = "link"
		entry.Address = parts[2]
		// Remaining params
		if len(parts) > 3 {
			entry.Params = strings.Join(parts[3:], " ")
		}
		return entry
	}

	// Unknown command type
	return nil
}

// calculateTopAddresses calculates the top N addresses by count
func calculateTopAddresses(addressCount map[string]int, topN int) []models.AddressCount {
	// Convert map to slice
	var counts []models.AddressCount
	for addr, count := range addressCount {
		counts = append(counts, models.AddressCount{
			Address: addr,
			Count:   count,
		})
	}

	// Sort by count descending
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		// Sort alphabetically if counts are equal
		return counts[i].Address < counts[j].Address
	})

	// Limit to top N
	if len(counts) > topN {
		counts = counts[:topN]
	}

	return counts
}

// extractTimezoneFromConf reads n2os.conf.user and extracts the timezone
// Format: "system time tz Australia/Perth"
func extractTimezoneFromConf(baseDir string, data *models.ArchiveData) {
	// Default to UTC if extraction fails
	data.Metadata.Timezone = "UTC"

	confPath := filepath.Join(baseDir, "data", "cfg", "n2os.conf.user")

	file, err := os.Open(confPath)
	if err != nil {
		// File doesn't exist, use default UTC
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for "system time tz" pattern
		if strings.Contains(line, "system time tz") {
			parts := strings.Fields(line)
			// Expected format: ["system", "time", "tz", "Australia/Perth"]
			if len(parts) >= 4 {
				timezone := parts[3]
				// Validate timezone by trying to load it
				if _, err := time.LoadLocation(timezone); err == nil {
					data.Metadata.Timezone = timezone
					return
				}
			}
		}
	}
}
