package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strings"
	"time"
)

// ParseDatabaseSampleData parses db-sampledata.txt dynamically
func ParseDatabaseSampleData(baseDir string, data *models.ArchiveData) error {
	filePath := filepath.Join(baseDir, "health_check", "pg_diag", "db-sampledata.txt")

	file, err := os.Open(filePath)
	if err != nil {
		return nil // Non-fatal: file might not exist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var tables []models.GenericTable
	var currentTable *models.GenericTable
	var columnHeaders []string
	state := searchingTableHeader

	for scanner.Scan() {
		line := scanner.Text()

		switch state {
		case searchingTableHeader:
			if tableName := extractTableName(line); tableName != "" {
				if currentTable != nil {
					tables = append(tables, *currentTable)
				}
				currentTable = &models.GenericTable{
					Name:    tableName,
					Columns: []string{},
					Rows:    []map[string]string{},
				}
				state = readingColumnHeaders
			}

		case readingColumnHeaders:
			if strings.TrimSpace(line) == "" {
				continue
			}
			columnHeaders = parseColumnHeaders(line)
			if len(columnHeaders) > 0 {
				currentTable.Columns = columnHeaders
				state = readingSeparator
			}

		case readingSeparator:
			if isSeparatorLine(line) {
				state = readingRows
			}

		case readingRows:
			if isRowCountLine(line) {
				rowCount := extractRowCount(line)
				currentTable.RowCount = rowCount
				currentTable.IsEmpty = (rowCount == 0)
				state = searchingTableHeader
				continue
			}

			if strings.TrimSpace(line) != "" {
				row := parseDataRow(line, columnHeaders)
				if row != nil {
					currentTable.Rows = append(currentTable.Rows, row)
				}
			}
		}
	}

	if currentTable != nil {
		tables = append(tables, *currentTable)
	}

	data.DatabaseSampleData = models.DatabaseSampleData{
		Tables:      tables,
		TotalTables: len(tables),
		ParsedAt:    time.Now(),
	}

	return scanner.Err()
}

type parseState int

const (
	searchingTableHeader parseState = iota
	readingColumnHeaders
	readingSeparator
	readingRows
)

func extractTableName(line string) string {
	re := regexp.MustCompile(`^([A-Z_]+)\s+-+`)
	matches := re.FindStringSubmatch(line)
	if len(matches) == 2 {
		return matches[1]
	}
	return ""
}

func parseColumnHeaders(line string) []string {
	parts := strings.Split(line, "|")
	columns := []string{}
	for _, part := range parts {
		colName := strings.TrimSpace(part)
		if colName != "" {
			columns = append(columns, colName)
		}
	}
	return columns
}

func isSeparatorLine(line string) bool {
	re := regexp.MustCompile(`^[\s\-\+]+$`)
	return re.MatchString(line)
}

func parseDataRow(line string, columnHeaders []string) map[string]string {
	parts := strings.Split(line, "|")
	row := make(map[string]string)

	for i, colName := range columnHeaders {
		if i < len(parts) {
			row[colName] = strings.TrimSpace(parts[i])
		} else {
			row[colName] = ""
		}
	}
	return row
}

func isRowCountLine(line string) bool {
	re := regexp.MustCompile(`^\(\d+\s+rows?\)`)
	return re.MatchString(strings.TrimSpace(line))
}

func extractRowCount(line string) int {
	re := regexp.MustCompile(`\((\d+)\s+rows?\)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) == 2 {
		var count int
		fmt.Sscanf(matches[1], "%d", &count)
		return count
	}
	return 0
}
