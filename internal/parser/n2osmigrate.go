package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strings"
)

// ParseN2OSMigrateLogs parses the n2osmigrate.log file
func ParseN2OSMigrateLogs(baseDir string, data *models.ArchiveData) error {
	logPath := filepath.Join(resolveN2OSLogDir(baseDir), "n2osmigrate.log")

	entries, summary, err := parseN2OSMigrateLogFile(logPath)
	if err != nil {
		// Non-fatal error - file may not exist
		return nil
	}

	data.N2OSMigrateLogs = entries
	data.N2OSMigrateSummary = summary

	return nil
}

// parseN2OSMigrateLogFile parses a single n2osmigrate.log file
func parseN2OSMigrateLogFile(path string) ([]models.N2OSMigrateLogEntry, models.N2OSMigrateSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, models.N2OSMigrateSummary{}, err
	}
	defer file.Close()

	var entries []models.N2OSMigrateLogEntry
	scanner := bufio.NewScanner(file)

	// Patterns for classification
	errorPattern := regexp.MustCompile(`^(rake aborted!|NN::|Tasks:|/usr/local/)`)
	warningPattern := regexp.MustCompile(`pw: no such user`)
	migrationItemsPattern := regexp.MustCompile(`DB Migration items:\s*(\d+)`)
	dbVersionPattern := regexp.MustCompile(`DB Current version:\s*(\d+)`)
	completionPattern := regexp.MustCompile(`All migrations performed!`)

	lineNumber := 0
	inErrorBlock := false
	var migrationItems, dbVersion string
	errorCount := 0
	warningCount := 0
	completedSuccess := false

	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		// Skip completely empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		var messageType string
		isMultiline := false

		// Check for "All migrations performed!"
		if completionPattern.MatchString(line) {
			completedSuccess = true
			messageType = "info"
		} else if strings.Contains(line, "rake aborted!") {
			// Start of error block
			inErrorBlock = true
			messageType = "error"
			errorCount++
		} else if inErrorBlock {
			// We're in an error block - check if this line is part of stacktrace
			if errorPattern.MatchString(line) || strings.HasPrefix(line, " ") || strings.Contains(line, "=>") {
				messageType = "error"
				isMultiline = true
			} else {
				// Exit error block
				inErrorBlock = false
				messageType = classifyNormalLine(line, warningPattern, migrationItemsPattern, dbVersionPattern)
			}
		} else {
			// Normal line classification
			messageType = classifyNormalLine(line, warningPattern, migrationItemsPattern, dbVersionPattern)
		}

		// Extract metrics
		if matches := migrationItemsPattern.FindStringSubmatch(line); len(matches) > 1 {
			migrationItems = matches[1]
		}
		if matches := dbVersionPattern.FindStringSubmatch(line); len(matches) > 1 {
			dbVersion = matches[1]
		}

		// Count warnings
		if messageType == "warning" {
			warningCount++
		}

		entry := models.N2OSMigrateLogEntry{
			LineNumber:  lineNumber,
			MessageType: messageType,
			Content:     line,
			IsMultiline: isMultiline,
		}

		entries = append(entries, entry)
	}

	// Build summary
	summary := models.N2OSMigrateSummary{
		TotalEntries:     len(entries),
		HasErrors:        errorCount > 0,
		ErrorCount:       errorCount,
		WarningCount:     warningCount,
		MigrationItems:   migrationItems,
		CurrentDBVersion: dbVersion,
		CompletedSuccess: completedSuccess,
	}

	return entries, summary, scanner.Err()
}

// classifyNormalLine classifies a line that's not part of an error block
func classifyNormalLine(line string, warningPattern, migrationItemsPattern, dbVersionPattern *regexp.Regexp) string {
	if warningPattern.MatchString(line) {
		return "warning"
	}
	if migrationItemsPattern.MatchString(line) || dbVersionPattern.MatchString(line) {
		return "metric"
	}
	return "info"
}
