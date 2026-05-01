package parser

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var copyHeaderRe = regexp.MustCompile(`^COPY public\.(\S+) \((.+)\) FROM stdin;$`)

const dbFileName = "penny_index.db"
const batchSize = 10_000
const barWidth = 30

func ParseBackupDump(dir string) (*models.BackupDump, error) {
	dump := &models.BackupDump{
		Tables: make(map[string]models.BackupTable),
	}
	if err := parseBackupMetaJSON(dir, dump); err != nil {
		return nil, err
	}

	pennyDir := filepath.Join(dir, ".penny")
	if err := os.MkdirAll(pennyDir, 0755); err != nil {
		return nil, fmt.Errorf("create .penny dir: %w", err)
	}
	dbPath := filepath.Join(pennyDir, dbFileName)
	dump.DBPath = dbPath

	// Use cached index if it exists
	if _, err := os.Stat(dbPath); err == nil {
		return loadCachedDump(dbPath, dump)
	}

	return buildDump(dir, dbPath, dump)
}

func loadCachedDump(dbPath string, dump *models.BackupDump) (*models.BackupDump, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open cached db: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT table_name, columns, row_count FROM _penny_meta ORDER BY table_name`)
	if err != nil {
		return nil, fmt.Errorf("read cached meta: %w", err)
	}
	defer rows.Close()

	totalRows := 0
	for rows.Next() {
		var name, colsJSON string
		var count int
		if err := rows.Scan(&name, &colsJSON, &count); err != nil {
			continue
		}
		var cols []string
		json.Unmarshal([]byte(colsJSON), &cols)
		dump.Tables[name] = models.BackupTable{Columns: cols, RowCount: count}
		totalRows += count
	}

	fmt.Printf("Using cached index (%s) — %d tables, %s rows\n",
		dbFileName, len(dump.Tables), fmtInt(totalRows))
	return dump, nil
}

func buildDump(dir, dbPath string, dump *models.BackupDump) (*models.BackupDump, error) {
	// Find the dump file
	matches, err := filepath.Glob(filepath.Join(dir, "dump-*"))
	if err != nil || len(matches) == 0 {
		return nil, fmt.Errorf("no dump-* file found in %s", dir)
	}
	dumpPath := matches[0]

	info, err := os.Stat(dumpPath)
	if err != nil {
		return nil, err
	}
	compressedSize := info.Size()

	f, err := os.Open(dumpPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Wrap file to count compressed bytes read
	var bytesRead atomic.Int64
	cr := &countingReader{r: f, n: &bytesRead}

	gz, err := gzip.NewReader(cr)
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	// Open SQLite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	// Tune SQLite for bulk insert speed
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-65536",
		"PRAGMA temp_store=MEMORY",
	} {
		db.Exec(pragma)
	}

	// Create metadata table
	db.Exec(`CREATE TABLE IF NOT EXISTS _penny_meta (
		table_name TEXT PRIMARY KEY,
		columns TEXT,
		row_count INTEGER
	)`)

	start := time.Now()
	var currentTable string
	var currentCols []string
	var tx *sql.Tx
	var stmt *sql.Stmt
	var batchCount int
	rowCounts := make(map[string]int)

	// Progress goroutine
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				printProgress(bytesRead.Load(), compressedSize, currentTable, rowCounts)
			}
		}
	}()

	commitBatch := func() {
		if tx != nil {
			if stmt != nil {
				stmt.Close()
				stmt = nil
			}
			tx.Commit()
			tx = nil
			batchCount = 0
		}
	}

	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 10*1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if m := copyHeaderRe.FindStringSubmatch(line); m != nil {
			commitBatch()
			currentTable = m[1]
			currentCols = parseColumns(m[2])
			rowCounts[currentTable] = 0

			// CREATE TABLE with TEXT columns (sanitize names)
			colDefs := make([]string, len(currentCols))
			for i, c := range currentCols {
				colDefs[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `" TEXT`
			}
			safeTable := strings.ReplaceAll(currentTable, `"`, `""`)
			db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS "%s"`, safeTable))
			db.Exec(fmt.Sprintf(`CREATE TABLE "%s" (%s)`, safeTable, strings.Join(colDefs, ", ")))
			continue
		}

		if line == `\.` {
			commitBatch()
			if currentTable != "" {
				// Store metadata
				colsJSON, _ := json.Marshal(currentCols)
				db.Exec(`INSERT OR REPLACE INTO _penny_meta (table_name, columns, row_count) VALUES (?, ?, ?)`,
					currentTable, string(colsJSON), rowCounts[currentTable])
				dump.Tables[currentTable] = models.BackupTable{
					Columns:  currentCols,
					RowCount: rowCounts[currentTable],
				}
			}
			currentTable = ""
			currentCols = nil
			continue
		}

		if currentTable == "" {
			continue
		}

		// Start a new transaction batch if needed
		if tx == nil {
			tx, _ = db.Begin()
			placeholders := strings.Repeat("?,", len(currentCols))
			placeholders = placeholders[:len(placeholders)-1]
			safeTable := strings.ReplaceAll(currentTable, `"`, `""`)
			stmt, _ = tx.Prepare(fmt.Sprintf(`INSERT INTO "%s" VALUES (%s)`, safeTable, placeholders))
		}

		fields := strings.Split(line, "\t")
		// Pad or trim to match column count
		for len(fields) < len(currentCols) {
			fields = append(fields, "")
		}
		args := make([]any, len(currentCols))
		for i := range currentCols {
			args[i] = fields[i]
		}
		stmt.Exec(args...)
		rowCounts[currentTable]++
		batchCount++

		if batchCount >= batchSize {
			commitBatch()
		}
	}

	commitBatch()
	close(done)

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	elapsed := time.Since(start)
	totalRows := 0
	for _, c := range rowCounts {
		totalRows += c
	}

	// Clear the progress line, print final status
	fmt.Printf("\rParsing backup dump... ✅ (%d tables, %s rows, %.1fs)%s\n",
		len(dump.Tables), fmtInt(totalRows), elapsed.Seconds(), strings.Repeat(" ", 20))

	return dump, nil
}

func printProgress(bytesRead, total int64, currentTable string, rowCounts map[string]int) {
	pct := 0.0
	if total > 0 {
		pct = float64(bytesRead) / float64(total) * 100
	}
	filled := int(float64(barWidth) * pct / 100)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	tableInfo := ""
	if currentTable != "" {
		tableInfo = fmt.Sprintf("  %s: %s rows", currentTable, fmtInt(rowCounts[currentTable]))
	}

	fmt.Printf("\rParsing backup dump... [%s] %3.0f%% (%s / %s)%s%-40s",
		bar, pct,
		fmtBytes(bytesRead), fmtBytes(total),
		tableInfo, "")
}

func fmtInt(n int) string {
	s := fmt.Sprintf("%d", n)
	out := []byte{}
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", n>>10)
	}
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func parseBackupMetaJSON(dir string, dump *models.BackupDump) error {
	data, err := os.ReadFile(filepath.Join(dir, "cfg", "meta.json"))
	if err != nil {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	dump.Meta.Nodes = m["nodes"]
	dump.Meta.Links = m["links"]
	dump.Meta.Variables = m["variables"]
	return nil
}

// parseColumns splits the column list from the COPY header, stripping quotes.
func parseColumns(raw string) []string {
	parts := strings.Split(raw, ", ")
	cols := make([]string, len(parts))
	for i, p := range parts {
		cols[i] = strings.Trim(strings.TrimSpace(p), `"`)
	}
	return cols
}
