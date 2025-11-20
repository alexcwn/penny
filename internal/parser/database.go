package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strconv"
	"strings"
)

// ParseDatabaseDiagnostics parses db-size.txt and db-stats.txt from pg_diag directory
func ParseDatabaseDiagnostics(baseDir string, data *models.ArchiveData) error {
	sizeFile := filepath.Join(baseDir, "health_check", "pg_diag", "db-size.txt")
	statsFile := filepath.Join(baseDir, "health_check", "pg_diag", "db-stats.txt")

	// Parse db-size.txt first
	sizeMap, totalBytes, err := parseDBSize(sizeFile)
	if err != nil {
		return err
	}

	// Parse db-stats.txt
	statsMap, err := parseDBStats(statsFile)
	if err != nil {
		return err
	}

	// Merge the two maps
	tables := mergeDatabaseData(sizeMap, statsMap)

	// Calculate issues count
	issuesCount := 0
	for _, table := range tables {
		if table.NeedsVacuum || table.IsOversized {
			issuesCount++
		}
	}

	data.Database = models.DatabaseDiagnostics{
		Tables:      tables,
		TotalSize:   formatBytes(totalBytes),
		IssuesCount: issuesCount,
	}

	return nil
}

// parseDBSize parses db-size.txt and returns a map of table name to size info
func parseDBSize(filePath string) (map[string]models.DatabaseTable, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	tables := make(map[string]models.DatabaseTable)
	scanner := bufio.NewScanner(file)
	totalBytes := int64(0)

	// Skip header lines
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip header (first 2 lines) and empty lines
		if lineNum <= 2 || strings.TrimSpace(line) == "" {
			continue
		}

		// Skip row count line at the end
		if strings.HasPrefix(line, "(") && strings.Contains(line, "rows)") {
			break
		}

		// Parse line: tablename | size
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			continue
		}

		tableName := strings.TrimSpace(parts[0])
		sizeStr := strings.TrimSpace(parts[1])

		// Parse size to bytes
		sizeBytes := parseSizeToBytes(sizeStr)
		totalBytes += sizeBytes

		tables[tableName] = models.DatabaseTable{
			TableName:   tableName,
			Size:        sizeStr,
			SizeBytes:   sizeBytes,
			IsOversized: sizeBytes >= 1024*1024*1024, // >= 1 GB
		}
	}

	return tables, totalBytes, scanner.Err()
}

// parseDBStats parses db-stats.txt and returns a map of table name to stats info
func parseDBStats(filePath string) (map[string]models.DatabaseTable, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tables := make(map[string]models.DatabaseTable)
	scanner := bufio.NewScanner(file)

	// Skip header lines
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip header (first 2 lines) and empty lines
		if lineNum <= 2 || strings.TrimSpace(line) == "" {
			continue
		}

		// Skip row count line at the end
		if strings.HasPrefix(line, "(") && strings.Contains(line, "rows)") {
			break
		}

		// Parse line: relname | last_vacuum | last_autovacuum | n_tup | dead_tup | av_threshold | expect_av
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}

		tableName := strings.TrimSpace(parts[0])
		lastVacuum := strings.TrimSpace(parts[1])
		lastAutovacuum := strings.TrimSpace(parts[2])
		nTupStr := strings.TrimSpace(parts[3])
		deadTupStr := strings.TrimSpace(parts[4])
		avThresholdStr := strings.TrimSpace(parts[5])

		// Parse numbers (handle commas)
		nTup := parseNumber(nTupStr)
		deadTup := parseNumber(deadTupStr)
		avThreshold := parseNumber(avThresholdStr)

		// Check if needs vacuum (dead tuples exceed threshold)
		needsVacuum := deadTup > 0 && deadTup >= avThreshold

		tables[tableName] = models.DatabaseTable{
			TableName:           tableName,
			LastVacuum:          lastVacuum,
			LastAutovacuum:      lastAutovacuum,
			LiveTuples:          nTup,
			DeadTuples:          deadTup,
			AutovacuumThreshold: avThreshold,
			NeedsVacuum:         needsVacuum,
		}
	}

	return tables, scanner.Err()
}

// mergeDatabaseData merges size and stats data into a single slice
func mergeDatabaseData(sizeMap, statsMap map[string]models.DatabaseTable) []models.DatabaseTable {
	merged := make([]models.DatabaseTable, 0, len(sizeMap))

	for tableName, sizeData := range sizeMap {
		table := sizeData

		// Merge stats if available
		if statsData, exists := statsMap[tableName]; exists {
			table.LastVacuum = statsData.LastVacuum
			table.LastAutovacuum = statsData.LastAutovacuum
			table.LiveTuples = statsData.LiveTuples
			table.DeadTuples = statsData.DeadTuples
			table.AutovacuumThreshold = statsData.AutovacuumThreshold
			table.NeedsVacuum = statsData.NeedsVacuum
		}

		merged = append(merged, table)
	}

	return merged
}

// parseSizeToBytes converts size string (e.g., "159 MB", "8192 bytes") to bytes
func parseSizeToBytes(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)

	// Parse number
	re := regexp.MustCompile(`^([\d.]+)\s*(.*)$`)
	matches := re.FindStringSubmatch(sizeStr)
	if len(matches) != 3 {
		return 0
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0
	}

	unit := strings.TrimSpace(matches[2])
	unit = strings.ToLower(unit)

	// Convert to bytes based on unit
	switch unit {
	case "bytes", "byte", "b":
		return int64(value)
	case "kb", "kib":
		return int64(value * 1024)
	case "mb", "mib":
		return int64(value * 1024 * 1024)
	case "gb", "gib":
		return int64(value * 1024 * 1024 * 1024)
	case "tb", "tib":
		return int64(value * 1024 * 1024 * 1024 * 1024)
	default:
		return 0
	}
}

// parseNumber parses a number string that may contain commas
func parseNumber(s string) int {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ",", "")

	// Handle -1 or empty
	if s == "" || s == "-1" {
		return 0
	}

	num, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return num
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
