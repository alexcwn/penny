package parser

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"sort"
	"strings"
	"time"
)

const logsDBFileName = "penny_logs.db"

// IndexLogs writes all parsed log data to a SQLite database in the archive output dir.
// If a valid cached DB exists (source hash matches), it returns immediately.
func IndexLogs(dir string, data *models.ArchiveData) error {
	pennyDir := filepath.Join(dir, ".penny")
	if err := os.MkdirAll(pennyDir, 0755); err != nil {
		return fmt.Errorf("create .penny dir: %w", err)
	}
	dbPath := filepath.Join(pennyDir, logsDBFileName)

	sourceHash, err := computeLogSourceHash(dir)
	if err != nil {
		return fmt.Errorf("compute source hash: %w", err)
	}

	if isLogCacheValid(dbPath, sourceHash) {
		fmt.Printf("  Using cached log index (%s)\n", logsDBFileName)
		return nil
	}

	// Remove stale DB before rebuild
	os.Remove(dbPath)

	fmt.Printf("  %s log index...\n", GetRandomVerb())
	start := time.Now()

	if err := buildLogsDB(dbPath, sourceHash, data); err != nil {
		return fmt.Errorf("build logs db: %w", err)
	}

	fmt.Printf("  Log index built in %.1fs (%s)\n", time.Since(start).Seconds(), logsDBFileName)
	return nil
}

func computeLogSourceHash(dir string) (string, error) {
	// All known log source paths (including rotation variants)
	candidates := []string{
		"data/log/messages",
		"data/log/auth.log",
		"data/log/auth.log.0",
		"data/log/auth.log.1",
		"data/log/auth.log.2",
		"data/log/auth.log.3",
		"data/log/auth.log.4",
		"data/log/auth.log.5",
		"data/log/auth.log.6",
		"data/log/security",
		"data/log/security.0",
		"data/log/security.0.bz2",
		"data/log/security.1",
		"data/log/security.1.bz2",
		"data/log/security.2",
		"data/log/security.2.bz2",
		"data/log/nginx-error.log",
		"data/log/nginx-access.log",
		"data/log/n2os/n2op.log",
		"data/log/n2os/n2osjobs.log",
		"data/log/n2os/production.log",
		"data/log/n2os/n2osmigrate.log",
		"data/log/n2os/n2os_ids.log",
		"data/log/n2os/n2os_ids_events.log",
		"data/log/n2os/n2os_alert.log",
		"data/log/n2os/n2os_alert_events.log",
		"data/log/n2os/n2os_cpe2cve.log",
		"data/log/n2os/n2os_rc.log",
		"data/log/n2os/n2os_rc_events.log",
		"data/log/n2os/n2os_reverse.log",
		"data/log/n2os/n2os_reverse_events.log",
		"data/log/n2os/n2os_trace.log",
		"data/log/n2os/n2os_trace_events.log",
		"data/log/n2os/n2os_sandbox.log",
		"data/log/n2os/n2os_sandbox_events.log",
		"data/log/n2os/n2os_va.log",
		"data/log/n2os/n2os_va_events.log",
		"data/log/n2os/n2os_stixdb.log",
		"data/log/n2os/n2os_strategist.log",
		"data/log/n2os/n2ossp.log",
		"data/log/n2os/puma.log",
		"data/log/n2os/puma-err.log",
		"data/log/n2os/n2os_otelcol.log",
		"health_check/health_logs.csv",
	}

	// Add rotation variants
	for i := 0; i <= 10; i++ {
		suffix := fmt.Sprintf(".%d", i)
		candidates = append(candidates,
			"data/log/messages"+suffix+".bz2",
			"data/log/nginx-error.log"+suffix+".bz2",
			"data/log/nginx-access.log"+suffix+".bz2",
		)
	}
	for i := 0; i <= 6; i++ {
		candidates = append(candidates, fmt.Sprintf("data/log/n2os/n2op.log.%d", i))
	}
	for i := 0; i <= 9; i++ {
		candidates = append(candidates,
			fmt.Sprintf("data/log/n2os/n2osjobs.log.%d", i),
			fmt.Sprintf("data/log/n2os/production.log.%d.gz", i),
			fmt.Sprintf("data/log/n2os/n2os_ids.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_ids_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_cpe2cve.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_rc.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_rc_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_reverse.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_reverse_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_trace.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_trace_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_sandbox.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_sandbox_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_va.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_va_events.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_stixdb.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_strategist.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2ossp.log.%d", i),
			fmt.Sprintf("data/log/n2os/puma.log.%d", i),
			fmt.Sprintf("data/log/n2os/puma-err.log.%d", i),
			fmt.Sprintf("data/log/n2os/n2os_otelcol.log.%d.bz2", i),
		)
	}

	var parts []string
	for _, rel := range candidates {
		full := filepath.Join(dir, rel)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", rel, info.ModTime().UnixNano()))
	}
	sort.Strings(parts)

	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return fmt.Sprintf("%x", h), nil
}

func isLogCacheValid(dbPath, sourceHash string) bool {
	if _, err := os.Stat(dbPath); err != nil {
		return false
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return false
	}
	defer db.Close()

	var stored string
	err = db.QueryRow(`SELECT source_hash FROM _penny_logs_meta WHERE table_name = 'logs_syslog'`).Scan(&stored)
	if err != nil {
		return false
	}
	return stored == sourceHash
}

func buildLogsDB(dbPath, sourceHash string, data *models.ArchiveData) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-65536",
		"PRAGMA temp_store=MEMORY",
	} {
		db.Exec(pragma)
	}

	if err := createLogsSchema(db); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	now := time.Now().Unix()

	type tableInsert struct {
		name string
		fn   func(*sql.DB) (int, error)
	}

	tables := []tableInsert{
		{"logs_syslog", func(db *sql.DB) (int, error) { return insertSyslog(db, data.Logs.Messages) }},
		{"logs_nginx_error", func(db *sql.DB) (int, error) { return insertNginxError(db, data.Logs.NginxErrors) }},
		{"logs_nginx_access", func(db *sql.DB) (int, error) { return insertNginxAccess(db, data.Logs.NginxAccess) }},
		{"logs_auth", func(db *sql.DB) (int, error) { return insertAuth(db, data.Logs.AuthLog) }},
		{"logs_n2op", func(db *sql.DB) (int, error) { return insertN2Op(db, data.N2OpLogs) }},
		{"logs_n2osjobs", func(db *sql.DB) (int, error) { return insertN2OSJobs(db, data.N2OSJobLogs) }},
		{"logs_n2osjobs_di", func(db *sql.DB) (int, error) { return insertN2OSJobDI(db, data.N2OSJobDILogs) }},
		{"logs_n2osdelayedjobs", func(db *sql.DB) (int, error) { return insertN2OSDelayedJobs(db, data.N2OSJobDelayedLogs) }},
		{"logs_production", func(db *sql.DB) (int, error) { return insertProduction(db, data.N2OSProductionLogs) }},
		{"logs_migrate", func(db *sql.DB) (int, error) { return insertMigrate(db, data.N2OSMigrateLogs) }},
		{"logs_n2os_ids", func(db *sql.DB) (int, error) { return insertN2OSIDS(db, data.N2OSIDSLogs) }},
		{"logs_n2os_ids_events", func(db *sql.DB) (int, error) { return insertN2OSIDSEvents(db, data.N2OSIDSEventsLogs) }},
		{"logs_n2os_alert", func(db *sql.DB) (int, error) { return insertN2OSAlert(db, data.N2OSAlertLogs) }},
		{"logs_n2os_alert_events", func(db *sql.DB) (int, error) { return insertN2OSAlertEvents(db, data.N2OSAlertEventsLogs) }},
		{"logs_n2os_cpe2cve", func(db *sql.DB) (int, error) { return insertN2OSCPE2CVE(db, data.N2OSCPE2CVELogs) }},
		{"logs_n2os_rc", func(db *sql.DB) (int, error) { return insertN2OSRC(db, data.N2OSRCLogs) }},
		{"logs_n2os_rc_events", func(db *sql.DB) (int, error) { return insertN2OSRCEvents(db, data.N2OSRCEventsLogs) }},
		{"logs_n2os_trace", func(db *sql.DB) (int, error) { return insertN2OSTrace(db, data.N2OSTraceLogs) }},
		{"logs_n2os_trace_events", func(db *sql.DB) (int, error) { return insertN2OSTraceEvents(db, data.N2OSTraceEventsLogs) }},
		{"logs_n2os_sandbox", func(db *sql.DB) (int, error) { return insertN2OSSandbox(db, data.N2OSSandboxLogs) }},
		{"logs_n2os_sandbox_events", func(db *sql.DB) (int, error) { return insertN2OSSandboxEvents(db, data.N2OSSandboxEventsLogs) }},
		{"logs_n2os_reverse", func(db *sql.DB) (int, error) { return insertN2OSReverse(db, data.N2OSReverseLogs) }},
		{"logs_n2os_reverse_events", func(db *sql.DB) (int, error) { return insertN2OSReverseEvents(db, data.N2OSReverseEventsLogs) }},
		{"logs_n2os_va", func(db *sql.DB) (int, error) { return insertN2OSVA(db, data.N2OSVALogs) }},
		{"logs_n2os_va_events", func(db *sql.DB) (int, error) { return insertN2OSVAEvents(db, data.N2OSVAEventsLogs) }},
		{"logs_n2os_stixdb", func(db *sql.DB) (int, error) { return insertN2OSStixDB(db, data.N2OSStixDBLogs) }},
		{"logs_n2os_strategist", func(db *sql.DB) (int, error) { return insertN2OSStrategist(db, data.N2OSStrategistLogs) }},
		{"logs_n2ossp", func(db *sql.DB) (int, error) { return insertN2OSSp(db, data.N2OSSpLogs) }},
		{"logs_puma", func(db *sql.DB) (int, error) { return insertN2OSPuma(db, data.N2OSPumaLogs) }},
		{"logs_puma_err", func(db *sql.DB) (int, error) { return insertN2OSPumaErr(db, data.N2OSPumaErrLogs) }},
		{"logs_n2os_otelcol", func(db *sql.DB) (int, error) { return insertN2OSOtelcol(db, data.N2OSOtelcolLogs) }},
		{"logs_health_events", func(db *sql.DB) (int, error) { return insertHealthEvents(db, data.HealthEvents) }},
	}

	rowCounts := make(map[string]int)
	for _, t := range tables {
		n, err := t.fn(db)
		if err != nil {
			return fmt.Errorf("insert %s: %w", t.name, err)
		}
		rowCounts[t.name] = n
	}

	// Build unified timeline table
	if err := buildUnifiedTable(db, data); err != nil {
		return fmt.Errorf("build unified table: %w", err)
	}
	unifiedCount, _ := queryCount(db, "logs_unified")
	rowCounts["logs_unified"] = unifiedCount

	// Populate FTS5 content tables
	if err := populateFTS(db); err != nil {
		return fmt.Errorf("populate fts: %w", err)
	}

	// Write meta
	metaStmt, err := db.Prepare(`INSERT OR REPLACE INTO _penny_logs_meta (table_name, row_count, source_hash, indexed_at) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer metaStmt.Close()
	for _, t := range tables {
		metaStmt.Exec(t.name, rowCounts[t.name], sourceHash, now)
	}
	metaStmt.Exec("logs_unified", rowCounts["logs_unified"], sourceHash, now)

	return nil
}

func createLogsSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS _penny_logs_meta (
			table_name  TEXT PRIMARY KEY,
			row_count   INTEGER NOT NULL DEFAULT 0,
			source_hash TEXT,
			indexed_at  INTEGER NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS logs_syslog (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			hostname TEXT, process TEXT, pid TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_syslog_ts      ON logs_syslog(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_syslog_level   ON logs_syslog(level)`,
		`CREATE INDEX IF NOT EXISTS idx_syslog_process ON logs_syslog(process)`,

		`CREATE TABLE IF NOT EXISTS logs_nginx_error (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			level TEXT, pid TEXT, tid TEXT, connection_id TEXT,
			message TEXT, client TEXT, server TEXT, request TEXT,
			upstream TEXT, host TEXT, referrer TEXT, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nginx_error_ts    ON logs_nginx_error(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_nginx_error_level ON logs_nginx_error(level)`,

		`CREATE TABLE IF NOT EXISTS logs_nginx_access (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			client_ip TEXT, method TEXT, status_code TEXT,
			message TEXT, level TEXT, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_nginx_access_ts     ON logs_nginx_access(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_nginx_access_status ON logs_nginx_access(status_code)`,

		`CREATE TABLE IF NOT EXISTS logs_auth (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			hostname TEXT, process TEXT, pid TEXT, user TEXT,
			event_type TEXT, sudo_user TEXT, command TEXT,
			source_ip TEXT, session_id TEXT, message TEXT,
			level TEXT, source TEXT, line_number INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_ts         ON logs_auth(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_type ON logs_auth(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_user       ON logs_auth(user)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_source_ip  ON logs_auth(source_ip)`,

		`CREATE TABLE IF NOT EXISTS logs_n2op (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			event_type TEXT, service TEXT, version TEXT,
			from_version TEXT, to_version TEXT, pid TEXT, thread_id TEXT, message TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2op_ts         ON logs_n2op(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2op_event_type ON logs_n2op(event_type)`,

		`CREATE TABLE IF NOT EXISTS logs_n2osjobs (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			task_name TEXT, duration_ms REAL, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osjobs_ts        ON logs_n2osjobs(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osjobs_task_name ON logs_n2osjobs(task_name)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osjobs_duration  ON logs_n2osjobs(duration_ms)`,

		`CREATE TABLE IF NOT EXISTS logs_n2osjobs_di (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			task_name TEXT, duration_ms REAL, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osjobs_di_ts        ON logs_n2osjobs_di(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osjobs_di_task_name ON logs_n2osjobs_di(task_name)`,

		`CREATE TABLE IF NOT EXISTS logs_n2osdelayedjobs (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			task_name TEXT, duration_ms REAL, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osdelayedjobs_ts        ON logs_n2osdelayedjobs(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2osdelayedjobs_task_name ON logs_n2osdelayedjobs(task_name)`,

		`CREATE TABLE IF NOT EXISTS logs_production (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_production_ts    ON logs_production(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_production_level ON logs_production(level)`,

		`CREATE TABLE IF NOT EXISTS logs_migrate (
			id INTEGER PRIMARY KEY, line_number INTEGER NOT NULL,
			message_type TEXT, content TEXT, is_multiline INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_migrate_message_type ON logs_migrate(message_type)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_ids (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_ids_ts    ON logs_n2os_ids(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_ids_level ON logs_n2os_ids(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_ids_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, protocol TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_ids_events_ts       ON logs_n2os_ids_events(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_ids_events_protocol ON logs_n2os_ids_events(protocol)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_alert (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_alert_ts    ON logs_n2os_alert(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_alert_level ON logs_n2os_alert(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_alert_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event_type TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_alert_events_ts         ON logs_n2os_alert_events(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_alert_events_event_type ON logs_n2os_alert_events(event_type)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_cpe2cve (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			message TEXT, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_cpe2cve_ts ON logs_n2os_cpe2cve(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_rc (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_rc_ts    ON logs_n2os_rc(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_rc_level ON logs_n2os_rc(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_rc_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_rc_events_ts ON logs_n2os_rc_events(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_trace (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_trace_ts    ON logs_n2os_trace(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_trace_level ON logs_n2os_trace(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_trace_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_trace_events_ts ON logs_n2os_trace_events(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_sandbox (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_sandbox_ts    ON logs_n2os_sandbox(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_sandbox_level ON logs_n2os_sandbox(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_sandbox_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_sandbox_events_ts ON logs_n2os_sandbox_events(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_reverse (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_reverse_ts    ON logs_n2os_reverse(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_reverse_level ON logs_n2os_reverse(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_reverse_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_reverse_events_ts ON logs_n2os_reverse_events(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_va (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_va_ts    ON logs_n2os_va(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_va_level ON logs_n2os_va(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_va_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			process_id TEXT, thread_id TEXT, event TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_va_events_ts ON logs_n2os_va_events(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_stixdb (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			message TEXT, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_stixdb_ts ON logs_n2os_stixdb(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_strategist (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			level TEXT, component TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_strategist_ts    ON logs_n2os_strategist(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_strategist_level ON logs_n2os_strategist(level)`,

		`CREATE TABLE IF NOT EXISTS logs_n2ossp (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			level TEXT, pid TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2ossp_ts    ON logs_n2ossp(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2ossp_level ON logs_n2ossp(level)`,

		`CREATE TABLE IF NOT EXISTS logs_puma (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			pid TEXT, level TEXT, message TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_puma_ts    ON logs_puma(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_puma_level ON logs_puma(level)`,

		`CREATE TABLE IF NOT EXISTS logs_puma_err (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			message TEXT, source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_puma_err_ts ON logs_puma_err(ts)`,

		`CREATE TABLE IF NOT EXISTS logs_n2os_otelcol (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			level TEXT, caller TEXT, message TEXT, fields TEXT,
			source TEXT, line_number INTEGER, raw_line TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_otelcol_ts    ON logs_n2os_otelcol(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_n2os_otelcol_level ON logs_n2os_otelcol(level)`,

		`CREATE TABLE IF NOT EXISTS logs_health_events (
			id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
			appliance_id TEXT, appliance_ip TEXT, appliance_host TEXT,
			category TEXT, event_type TEXT, severity TEXT,
			description TEXT, info_json TEXT,
			synchronized INTEGER, replicated INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_health_events_ts           ON logs_health_events(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_health_events_severity     ON logs_health_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_health_events_category     ON logs_health_events(category)`,
		`CREATE INDEX IF NOT EXISTS idx_health_events_appliance_ip ON logs_health_events(appliance_ip)`,

		`CREATE TABLE IF NOT EXISTS logs_unified (
			id          INTEGER PRIMARY KEY,
			ts          INTEGER NOT NULL,
			source_type TEXT NOT NULL,
			level       TEXT,
			message     TEXT,
			source_id   INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_unified_ts          ON logs_unified(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_unified_source_type ON logs_unified(source_type)`,
		`CREATE INDEX IF NOT EXISTS idx_unified_level       ON logs_unified(level)`,
		`CREATE INDEX IF NOT EXISTS idx_unified_type_ts     ON logs_unified(source_type, ts)`,

		// FTS5 content tables (no data duplication)
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_syslog      USING fts5(message, content=logs_syslog,        content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_ids    USING fts5(message, content=logs_n2os_ids,      content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_production  USING fts5(message, content=logs_production,    content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_alert  USING fts5(message, content=logs_n2os_alert,    content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_health      USING fts5(description, content=logs_health_events, content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_cpe2cve USING fts5(message, content=logs_n2os_cpe2cve, content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_rc      USING fts5(message, content=logs_n2os_rc,      content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_otelcol USING fts5(message, content=logs_n2os_otelcol, content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_reverse  USING fts5(message, content=logs_n2os_reverse,  content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_trace    USING fts5(message, content=logs_n2os_trace,    content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_sandbox  USING fts5(message, content=logs_n2os_sandbox,  content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_va       USING fts5(message, content=logs_n2os_va,       content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_stixdb      USING fts5(message, content=logs_n2os_stixdb,      content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2os_strategist  USING fts5(message, content=logs_n2os_strategist,  content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_n2ossp  USING fts5(message, content=logs_n2ossp,  content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_puma    USING fts5(message, content=logs_puma,    content_rowid=id)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS fts_unified     USING fts5(message, content=logs_unified,       content_rowid=id)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("exec %q: %w", s[:min(40, len(s))], err)
		}
	}
	return nil
}

// --- batch insert helpers ---

func insertSyslog(db *sql.DB, entries []models.LogEntry) (int, error) {
	tx, stmt, err := beginBatch(db, `INSERT INTO logs_syslog (ts,hostname,process,pid,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Hostname, e.Process, e.PID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, `INSERT INTO logs_syslog (ts,hostname,process,pid,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertNginxError(db *sql.DB, entries []models.NginxLogEntry) (int, error) {
	q := `INSERT INTO logs_nginx_error (ts,level,pid,tid,connection_id,message,client,server,request,upstream,host,referrer,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Level, e.PID, e.TID, e.ConnectionID, e.Message, e.Client, e.Server, e.Request, e.Upstream, e.Host, e.Referrer, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertNginxAccess(db *sql.DB, entries []models.LogEntry) (int, error) {
	// NginxAccess uses LogEntry: Hostname→client_ip, Process→method, PID→status_code
	q := `INSERT INTO logs_nginx_access (ts,client_ip,method,status_code,message,level,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Hostname, e.Process, e.PID, e.Message, e.Level, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertAuth(db *sql.DB, entries []models.AuthLogEntry) (int, error) {
	q := `INSERT INTO logs_auth (ts,hostname,process,pid,user,event_type,sudo_user,command,source_ip,session_id,message,level,source,line_number) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		src := e.Source
		if src == "" {
			src = "auth"
		}
		stmt.Exec(e.Timestamp.UnixNano(), e.Hostname, e.Process, e.PID, e.User, string(e.EventType), e.SudoUser, e.Command, e.SourceIP, e.SessionID, e.Message, e.Level, src, 0)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2Op(db *sql.DB, entries []models.N2OpLogEntry) (int, error) {
	q := `INSERT INTO logs_n2op (ts,event_type,service,version,from_version,to_version,pid,thread_id,message) VALUES (?,?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), string(e.EventType), e.Service, e.Version, e.FromVersion, e.ToVersion, e.PID, e.ThreadID, e.Message)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSJobs(db *sql.DB, entries []models.N2OSJobLogEntry) (int, error) {
	q := `INSERT INTO logs_n2osjobs (ts,task_name,duration_ms,source,line_number,raw_line) VALUES (?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.TaskName, e.DurationMS, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSDelayedJobs(db *sql.DB, entries []models.N2OSJobDelayedLogEntry) (int, error) {
	q := `INSERT INTO logs_n2osdelayedjobs (ts,task_name,duration_ms,source,line_number,raw_line) VALUES (?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.TaskName, e.DurationMS, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSJobDI(db *sql.DB, entries []models.N2OSJobDILogEntry) (int, error) {
	q := `INSERT INTO logs_n2osjobs_di (ts,task_name,duration_ms,source,line_number,raw_line) VALUES (?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.TaskName, e.DurationMS, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertProduction(db *sql.DB, entries []models.N2OSProductionLogEntry) (int, error) {
	q := `INSERT INTO logs_production (ts,process_id,level,message,source,line_number) VALUES (?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.Level, e.Message, e.Source, e.LineNumber)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertMigrate(db *sql.DB, entries []models.N2OSMigrateLogEntry) (int, error) {
	q := `INSERT INTO logs_migrate (line_number,message_type,content,is_multiline) VALUES (?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		multiline := 0
		if e.IsMultiline {
			multiline = 1
		}
		stmt.Exec(e.LineNumber, e.MessageType, e.Content, multiline)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSIDS(db *sql.DB, entries []models.N2OSIDSLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_ids (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSIDSEvents(db *sql.DB, entries []models.N2OSIDSEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_ids_events (ts,process_id,thread_id,protocol,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Protocol, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSAlert(db *sql.DB, entries []models.N2OSAlertLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_alert (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSAlertEvents(db *sql.DB, entries []models.N2OSAlertEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_alert_events (ts,process_id,thread_id,event_type,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.EventType, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSOtelcol(db *sql.DB, entries []models.N2OSOtelcolLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_otelcol (ts,level,caller,message,fields,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Level, e.Caller, e.Message, e.Fields, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSCPE2CVE(db *sql.DB, entries []models.N2OSCPE2CVELogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_cpe2cve (ts,message,source,line_number,raw_line) VALUES (?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSRC(db *sql.DB, entries []models.N2OSRCLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_rc (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSRCEvents(db *sql.DB, entries []models.N2OSRCEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_rc_events (ts,process_id,thread_id,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSTrace(db *sql.DB, entries []models.N2OSTraceLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_trace (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSTraceEvents(db *sql.DB, entries []models.N2OSTraceEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_trace_events (ts,process_id,thread_id,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSSandbox(db *sql.DB, entries []models.N2OSSandboxLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_sandbox (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSSandboxEvents(db *sql.DB, entries []models.N2OSSandboxEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_sandbox_events (ts,process_id,thread_id,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSReverse(db *sql.DB, entries []models.N2OSReverseLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_reverse (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSReverseEvents(db *sql.DB, entries []models.N2OSReverseEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_reverse_events (ts,process_id,thread_id,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSVA(db *sql.DB, entries []models.N2OSVALogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_va (ts,process_id,thread_id,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSVAEvents(db *sql.DB, entries []models.N2OSVAEventsLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_va_events (ts,process_id,thread_id,event,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.ProcessID, e.ThreadID, e.Event, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSPuma(db *sql.DB, entries []models.N2OSPumaLogEntry) (int, error) {
	q := `INSERT INTO logs_puma (ts,pid,level,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.PID, e.Level, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSPumaErr(db *sql.DB, entries []models.N2OSPumaErrLogEntry) (int, error) {
	q := `INSERT INTO logs_puma_err (ts,message,source,line_number,raw_line) VALUES (?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSSp(db *sql.DB, entries []models.N2OSSpLogEntry) (int, error) {
	q := `INSERT INTO logs_n2ossp (ts,level,pid,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Level, e.PID, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSStrategist(db *sql.DB, entries []models.N2OSStrategistLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_strategist (ts,level,component,message,source,line_number,raw_line) VALUES (?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Level, e.Component, e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertN2OSStixDB(db *sql.DB, entries []models.N2OSStixDBLogEntry) (int, error) {
	q := `INSERT INTO logs_n2os_stixdb (ts,message,source,line_number,raw_line) VALUES (?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		stmt.Exec(e.Timestamp.UnixNano(), e.Message, e.Source, e.LineNumber, e.RawLine)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

func insertHealthEvents(db *sql.DB, entries []models.HealthEvent) (int, error) {
	q := `INSERT INTO logs_health_events (ts,appliance_id,appliance_ip,appliance_host,category,event_type,severity,description,info_json,synchronized,replicated) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	tx, stmt, err := beginBatch(db, q)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		sync := 0
		if e.Synchronized {
			sync = 1
		}
		repl := 0
		if e.Replicated {
			repl = 1
		}
		stmt.Exec(e.Timestamp.UnixNano(), e.ApplianceID, e.ApplianceIP, e.ApplianceHost, string(e.Category), string(e.EventType), string(e.Severity), e.Description, e.InfoJSON, sync, repl)
		count++
		if count%batchSize == 0 {
			tx, stmt, err = rotateBatch(tx, stmt, db, q)
			if err != nil {
				return count, err
			}
		}
	}
	return count, commitBatchFinal(tx, stmt)
}

// buildUnifiedTable materialises all timestamped log types into logs_unified.
// logs_migrate is excluded (no timestamps).
func buildUnifiedTable(db *sql.DB, data *models.ArchiveData) error {
	type unifiedRow struct {
		ts         int64
		sourceType string
		level      string
		message    string
		sourceID   int64
	}

	// We INSERT INTO logs_unified by querying each typed table after it's been written.
	type tableMapping struct {
		sourceType    string
		table         string
		levelCol      string // empty if no level column
		messageCol    string
	}

	mappings := []tableMapping{
		{"syslog", "logs_syslog", "level", "message"},
		{"nginx_error", "logs_nginx_error", "level", "message"},
		{"nginx_access", "logs_nginx_access", "level", "message"},
		{"auth", "logs_auth", "level", "message"},
		{"n2op", "logs_n2op", "event_type", "message"},
		{"n2osjobs", "logs_n2osjobs", "", "task_name"},
		{"n2osjobs_di", "logs_n2osjobs_di", "", "task_name"},
		{"n2osdelayedjobs", "logs_n2osdelayedjobs", "", "task_name"},
		{"production", "logs_production", "level", "message"},
		{"n2os_ids", "logs_n2os_ids", "level", "message"},
		{"n2os_ids_events", "logs_n2os_ids_events", "protocol", "event"},
		{"n2os_alert", "logs_n2os_alert", "level", "message"},
		{"n2os_alert_events", "logs_n2os_alert_events", "event_type", "event"},
		{"n2os_cpe2cve", "logs_n2os_cpe2cve", "", "message"},
		{"n2os_rc", "logs_n2os_rc", "level", "message"},
		{"n2os_rc_events", "logs_n2os_rc_events", "", "event"},
		{"n2os_trace", "logs_n2os_trace", "level", "message"},
		{"n2os_trace_events", "logs_n2os_trace_events", "", "event"},
		{"n2os_sandbox", "logs_n2os_sandbox", "level", "message"},
		{"n2os_sandbox_events", "logs_n2os_sandbox_events", "", "event"},
		{"n2os_reverse", "logs_n2os_reverse", "level", "message"},
		{"n2os_reverse_events", "logs_n2os_reverse_events", "", "event"},
		{"n2os_va", "logs_n2os_va", "level", "message"},
		{"n2os_va_events", "logs_n2os_va_events", "", "event"},
		{"n2os_stixdb", "logs_n2os_stixdb", "", "message"},
		{"n2os_strategist", "logs_n2os_strategist", "level", "message"},
		{"n2ossp", "logs_n2ossp", "level", "message"},
		{"puma", "logs_puma", "level", "message"},
		{"puma_err", "logs_puma_err", "", "message"},
		{"n2os_otelcol", "logs_n2os_otelcol", "level", "message"},
		{"health_events", "logs_health_events", "severity", "description"},
	}

	insertQ := `INSERT INTO logs_unified (ts, source_type, level, message, source_id) VALUES (?, ?, ?, ?, ?)`
	tx, stmt, err := beginBatch(db, insertQ)
	if err != nil {
		return err
	}

	count := 0
	for _, m := range mappings {
		levelExpr := "''"
		if m.levelCol != "" {
			levelExpr = m.levelCol
		}
		query := fmt.Sprintf("SELECT id, ts, %s, %s FROM %s", levelExpr, m.messageCol, m.table)
		rows, err := db.Query(query)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id int64
			var ts int64
			var level, message string
			if err := rows.Scan(&id, &ts, &level, &message); err != nil {
				continue
			}
			stmt.Exec(ts, m.sourceType, level, message, id)
			count++
			if count%batchSize == 0 {
				tx, stmt, err = rotateBatch(tx, stmt, db, insertQ)
				if err != nil {
					rows.Close()
					return err
				}
			}
		}
		rows.Close()
	}

	return commitBatchFinal(tx, stmt)
}

// populateFTS inserts rowids into FTS5 content tables.
func populateFTS(db *sql.DB) error {
	type ftsTable struct {
		fts     string
		content string
		col     string
	}
	tables := []ftsTable{
		{"fts_syslog", "logs_syslog", "message"},
		{"fts_n2os_ids", "logs_n2os_ids", "message"},
		{"fts_production", "logs_production", "message"},
		{"fts_n2os_alert", "logs_n2os_alert", "message"},
		{"fts_n2os_cpe2cve", "logs_n2os_cpe2cve", "message"},
		{"fts_n2os_rc", "logs_n2os_rc", "message"},
		{"fts_n2os_otelcol", "logs_n2os_otelcol", "message"},
		{"fts_n2os_trace",   "logs_n2os_trace",   "message"},
		{"fts_n2os_sandbox", "logs_n2os_sandbox", "message"},
		{"fts_n2os_reverse", "logs_n2os_reverse", "message"},
		{"fts_n2os_va",     "logs_n2os_va",     "message"},
		{"fts_n2os_stixdb",     "logs_n2os_stixdb",     "message"},
		{"fts_n2os_strategist", "logs_n2os_strategist", "message"},
		{"fts_n2ossp", "logs_n2ossp", "message"},
		{"fts_puma",   "logs_puma",   "message"},
		{"fts_health", "logs_health_events", "description"},
		{"fts_unified", "logs_unified", "message"},
	}
	for _, t := range tables {
		q := fmt.Sprintf(`INSERT INTO %s(rowid, %s) SELECT id, %s FROM %s`, t.fts, t.col, t.col, t.content)
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("populate %s: %w", t.fts, err)
		}
	}
	return nil
}

// --- transaction helpers ---

func beginBatch(db *sql.DB, query string) (*sql.Tx, *sql.Stmt, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, nil, err
	}
	stmt, err := tx.Prepare(query)
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, stmt, nil
}

func rotateBatch(tx *sql.Tx, stmt *sql.Stmt, db *sql.DB, query string) (*sql.Tx, *sql.Stmt, error) {
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return beginBatch(db, query)
}

func commitBatchFinal(tx *sql.Tx, stmt *sql.Stmt) error {
	if stmt != nil {
		stmt.Close()
	}
	if tx != nil {
		return tx.Commit()
	}
	return nil
}

func queryCount(db *sql.DB, table string) (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
