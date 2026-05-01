package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"penny/internal/models"
	"penny/internal/pennyconfig"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var archiveData *models.ArchiveData
var backupData *models.BackupDump
var logsDB *sql.DB
var pennyVersion string

// SetArchiveData sets the parsed archive data for handlers to use
func SetArchiveData(data *models.ArchiveData) {
	archiveData = data
}

// SetBackupData sets the parsed backup dump for handlers to use
func SetBackupData(data *models.BackupDump) {
	backupData = data
}

// SetLogsDB sets the SQLite log database for log handlers to use
func SetLogsDB(db *sql.DB) {
	logsDB = db
}

func SetPennyVersion(v string) { pennyVersion = v }

func handleVersion(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, map[string]string{"version": pennyVersion})
}

func handleBackupData(w http.ResponseWriter, r *http.Request) {
	if backupData == nil {
		http.Error(w, "No backup data loaded", http.StatusInternalServerError)
		return
	}
	respondJSON(w, backupData)
}

func handleBackupTable(w http.ResponseWriter, r *http.Request) {
	if backupData == nil {
		http.Error(w, "No backup data loaded", http.StatusInternalServerError)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name param", http.StatusBadRequest)
		return
	}

	tbl, ok := backupData.Tables[name]
	if !ok {
		http.Error(w, "unknown table", http.StatusNotFound)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	if size <= 0 || size > 250 {
		size = 50
	}
	if page < 0 {
		page = 0
	}

	sortCol := r.URL.Query().Get("sort")
	sortDir := r.URL.Query().Get("dir")
	if sortDir != "desc" {
		sortDir = "asc"
	}

	// Build WHERE clause from col_N=value params
	var whereClauses []string
	var whereArgs []any
	for i, col := range tbl.Columns {
		v := r.URL.Query().Get(fmt.Sprintf("col_%d", i))
		if v != "" {
			safeCol := `"` + strings.ReplaceAll(col, `"`, `""`) + `"`
			whereClauses = append(whereClauses, safeCol+` LIKE ?`)
			whereArgs = append(whereArgs, "%"+v+"%")
		}
	}

	safeTable := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`

	where := ""
	if len(whereClauses) > 0 {
		where = " WHERE " + strings.Join(whereClauses, " AND ")
	}

	orderBy := ""
	if sortCol != "" {
		safeSort := `"` + strings.ReplaceAll(sortCol, `"`, `""`) + `"`
		dir := "ASC"
		if sortDir == "desc" {
			dir = "DESC"
		}
		orderBy = " ORDER BY " + safeSort + " " + dir
	}

	db, err := sql.Open("sqlite", backupData.DBPath)
	if err != nil {
		http.Error(w, "db open error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Count rows — use stored count when unfiltered (avoids 10s full table scan),
	// cap filtered count at 100,001 so SQLite stops early instead of scanning 3M rows.
	const countCap = 100_001
	var totalCount int
	if len(whereClauses) == 0 {
		totalCount = tbl.RowCount
	} else {
		db.QueryRow("SELECT COUNT(*) FROM "+safeTable+where+" LIMIT "+strconv.Itoa(countCap), whereArgs...).Scan(&totalCount)
	}

	totalPages := int(math.Ceil(float64(totalCount) / float64(size)))
	if totalPages < 1 {
		totalPages = 1
	}
	if page >= totalPages {
		page = totalPages - 1
	}

	offset := page * size
	query := fmt.Sprintf("SELECT * FROM %s%s%s LIMIT %d OFFSET %d",
		safeTable, where, orderBy, size, offset)

	sqlRows, err := db.Query(query, whereArgs...)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer sqlRows.Close()

	cols, _ := sqlRows.Columns()
	var rows [][]string
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for sqlRows.Next() {
		sqlRows.Scan(ptrs...)
		row := make([]string, len(cols))
		for i, v := range vals {
			if v.Valid {
				row[i] = v.String
			} else {
				row[i] = `\N`
			}
		}
		rows = append(rows, row)
	}
	if rows == nil {
		rows = [][]string{}
	}

	respondJSON(w, map[string]any{
		"columns":     cols,
		"rows":        rows,
		"total_count": totalCount,
		"page":        page,
		"total_pages": totalPages,
	})
}

// handleMetadata returns basic archive metadata
func handleMetadata(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.Metadata)
}

// handleSystemInfo returns system information
func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.SystemInfo)
}

// handleLogs returns log entries with optional filtering and pagination.
// Queries SQLite tables: logs_syslog, logs_nginx_error, logs_nginx_access, logs_auth.
func handleLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	logType := r.URL.Query().Get("type")
	level := r.URL.Query().Get("level")
	eventType := r.URL.Query().Get("event_type")
	authUser := r.URL.Query().Get("auth_user")
	sourceIP := r.URL.Query().Get("source_ip")
	q := r.URL.Query().Get("q")
	limit, offset := paginateQuery(r)
	from, to := timeRangeFilter(r)

	switch logType {
	case "nginx":
		var where []string
		var args []any
		if level != "" {
			where, args = appendWhere(where, args, "level = ?", level)
		}
		where, args = appendTimeRange(where, args, from, to)
		rows, total, err := queryLogTable(logsDB, "logs_nginx_error",
			"id,ts,level,pid,tid,connection_id,message,client,server,request,upstream,host,referrer,source,line_number,raw_line",
			where, args, limit, offset, "ts ASC")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, "logs", rows, total, limit, offset)

	case "nginx-access":
		var where []string
		var args []any
		if level != "" {
			where, args = appendWhere(where, args, "level = ?", level)
		}
		where, args = appendTimeRange(where, args, from, to)
		rows, total, err := queryLogTable(logsDB, "logs_nginx_access",
			"id,ts,client_ip,method,status_code,message,level,source,line_number,raw_line",
			where, args, limit, offset, "ts ASC")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, "logs", rows, total, limit, offset)

	case "auth":
		var where []string
		var args []any
		if eventType != "" {
			where, args = appendWhere(where, args, "event_type = ?", eventType)
		}
		if authUser != "" {
			where, args = appendWhere(where, args, "(user LIKE ? OR sudo_user LIKE ?)", "%"+authUser+"%", "%"+authUser+"%")
		}
		if sourceIP != "" {
			where, args = appendWhere(where, args, "source_ip LIKE ?", "%"+sourceIP+"%")
		}
		if level != "" {
			where, args = appendWhere(where, args, "level = ?", level)
		}
		where, args = appendTimeRange(where, args, from, to)
		rows, total, err := queryLogTable(logsDB, "logs_auth",
			"id,ts,hostname,process,pid,user,event_type,sudo_user,command,source_ip,session_id,message,level,source,line_number",
			where, args, limit, offset, "ts ASC")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, "logs", rows, total, limit, offset)

	case "messages", "syslog", "":
		var where []string
		var args []any
		if level != "" {
			where, args = appendWhere(where, args, "level = ?", level)
		}
		where, args = appendTimeRange(where, args, from, to)
		if q != "" {
			rows, total, err := queryFTS(logsDB, "fts_syslog", "logs_syslog",
				"id,ts,hostname,process,pid,level,message,source,line_number,raw_line",
				q, where, args, limit, offset)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondLogs(w, r, "logs", rows, total, limit, offset)
			return
		}
		rows, total, err := queryLogTable(logsDB, "logs_syslog",
			"id,ts,hostname,process,pid,level,message,source,line_number,raw_line",
			where, args, limit, offset, "ts ASC")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, "logs", rows, total, limit, offset)

	default:
		http.Error(w, "Invalid log type", http.StatusBadRequest)
	}
}

// handleProcesses returns process list
func handleProcesses(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Optional filtering by user
	user := r.URL.Query().Get("user")
	processes := archiveData.Processes

	if user != "" {
		var filtered []models.Process
		for _, p := range processes {
			if p.User == user {
				filtered = append(filtered, p)
			}
		}
		processes = filtered
	}

	respondJSON(w, processes)
}

// handleNetwork returns network configuration
func handleNetwork(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.NetworkConfig)
}

// handleBPFStats returns BPF statistics
func handleBPFStats(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"snapshots":   archiveData.BPFSnapshots,
		"comparisons": archiveData.BPFComparisons,
	}

	respondJSON(w, response)
}

// handleStorage returns storage information
func handleStorage(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.Storage)
}

// handleN2OSConfig returns N2OS configuration
func handleN2OSConfig(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSConfig)
}

// handleN2OpLogs returns N2OS operation logs with optional filtering and pagination.
func handleN2OpLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if et := r.URL.Query().Get("event_type"); et != "" {
		where, args = appendWhere(where, args, "event_type = ?", et)
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_n2op",
		"id,ts,event_type,service,version,from_version,to_version,pid,thread_id,message",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, map[string]any{
		"logs":       rows,
		"violations": archiveData.UpgradeViolations,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	})
}

// handleN2OSJobLogs returns N2OS job logs (background tasks).
func handleN2OSJobLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if task := r.URL.Query().Get("task_name"); task != "" {
		where, args = appendWhere(where, args, "task_name LIKE ?", "%"+task+"%")
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_n2osjobs",
		"id,ts,task_name,duration_ms,source,line_number,raw_line",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondLogs(w, r, "logs", rows, total, limit, offset)
}

// handleN2OSDelayedJobLogs returns N2OS delayed job logs.
func handleN2OSDelayedJobLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if task := r.URL.Query().Get("task_name"); task != "" {
		where, args = appendWhere(where, args, "task_name LIKE ?", "%"+task+"%")
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_n2osdelayedjobs",
		"id,ts,task_name,duration_ms,source,line_number,raw_line",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondLogs(w, r, "logs", rows, total, limit, offset)
}

// handleN2OSJobDILogs returns N2OS job DI logs (data integration tasks).
func handleN2OSJobDILogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if task := r.URL.Query().Get("task_name"); task != "" {
		where, args = appendWhere(where, args, "task_name LIKE ?", "%"+task+"%")
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_n2osjobs_di",
		"id,ts,task_name,duration_ms,source,line_number,raw_line",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondLogs(w, r, "logs", rows, total, limit, offset)
}

// handleN2OSMigrateLogs returns N2OS migration logs.
func handleN2OSMigrateLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if mt := r.URL.Query().Get("message_type"); mt != "" {
		where, args = appendWhere(where, args, "message_type = ?", mt)
	}
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_migrate",
		"id,line_number,message_type,content,is_multiline",
		where, args, limit, offset, "line_number ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, map[string]any{
		"summary": archiveData.N2OSMigrateSummary,
		"entries": rows,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleAuthLogs returns auth.log entries with optional filtering and pagination.
func handleAuthLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if level := r.URL.Query().Get("level"); level != "" {
		where, args = appendWhere(where, args, "level = ?", level)
	}
	if eventType := r.URL.Query().Get("event_type"); eventType != "" {
		where, args = appendWhere(where, args, "event_type = ?", eventType)
	}
	if user := r.URL.Query().Get("user"); user != "" {
		where, args = appendWhere(where, args, "(user LIKE ? OR sudo_user LIKE ?)", "%"+user+"%", "%"+user+"%")
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)

	rows, total, err := queryLogTable(logsDB, "logs_auth",
		"id,ts,hostname,process,pid,user,event_type,sudo_user,command,source_ip,session_id,message,level,source,line_number",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondLogs(w, r, "logs", rows, total, limit, offset)
}

// handleHealthEvents returns health events with optional filtering and pagination.
func handleHealthEvents(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any
	if cat := r.URL.Query().Get("category"); cat != "" {
		where, args = appendWhere(where, args, "category = ?", cat)
	}
	if et := r.URL.Query().Get("event_type"); et != "" {
		where, args = appendWhere(where, args, "event_type = ?", et)
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		where, args = appendWhere(where, args, "severity = ?", sev)
	}
	if app := r.URL.Query().Get("appliance"); app != "" {
		where, args = appendWhere(where, args, "appliance_host LIKE ?", "%"+app+"%")
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)
	q := r.URL.Query().Get("q")

	if q != "" {
		rows, total, err := queryFTS(logsDB, "fts_health", "logs_health_events",
			"id,ts,appliance_id,appliance_ip,appliance_host,category,event_type,severity,description,info_json,synchronized,replicated",
			q, where, args, limit, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, "events", rows, total, limit, offset)
		return
	}

	rows, total, err := queryLogTable(logsDB, "logs_health_events",
		"id,ts,appliance_id,appliance_ip,appliance_host,category,event_type,severity,description,info_json,synchronized,replicated",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondLogs(w, r, "events", rows, total, limit, offset)
}

// handleDatabase returns database diagnostics
func handleDatabase(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.Database)
}

// handleDatabaseSampleData returns database sample data
func handleDatabaseSampleData(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.DatabaseSampleData)
}

// handleAppliances returns appliance data with optional filtering
func handleAppliances(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Optional filtering
	site := r.URL.Query().Get("site")
	model := r.URL.Query().Get("model")

	appliances := archiveData.Appliances

	// Apply filters if provided
	if site != "" || model != "" {
		var filtered []models.Appliance
		for _, a := range appliances {
			if (site == "" || a.Site == site) &&
				(model == "" || a.Model == model) {
				filtered = append(filtered, a)
			}
		}
		appliances = filtered
	}

	respondJSON(w, appliances)
}

// handleN2OSConf returns N2OS configuration data
func handleN2OSConf(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSConfData)
}

// handleOverview returns a summary of key metrics
func handleOverview(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	overview := map[string]any{
		"metadata":        archiveData.Metadata,
		"system_info":     archiveData.SystemInfo,
		"total_logs":      countTable("logs_syslog") + countTable("logs_nginx_error") + countTable("logs_auth"),
		"total_processes": len(archiveData.Processes),
		"error_count":     countErrors(),
		"warning_count":   countWarnings(),
		"critical_count":  countCritical(),
		"top_processes":   getTopProcesses(10),
		"log_summary":     getLogSummary(),
	}

	respondJSON(w, overview)
}

// handleDashboard returns a dashboard payload: known issues and system vitals.
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	knownIssues := archiveData.KnownIssueResults
	if knownIssues == nil {
		knownIssues = []models.KnownIssueResult{}
	}

	respondJSON(w, map[string]interface{}{
		"known_issues": knownIssues,
		"system": map[string]string{
			"version":  archiveData.SystemInfo.Version,
			"hostname": archiveData.Metadata.Hostname,
			"platform": archiveData.SystemInfo.Platform,
			"uptime":   archiveData.SystemInfo.Uptime,
		},
	})
}

// --- Generic log handler factory ---

type logHandlerConfig struct {
	table     string // e.g. "logs_n2os_ids"
	cols      string // comma-separated column list
	ftsTable  string // e.g. "fts_n2os_ids" — empty means no FTS support
	filter    string // query param name for optional equality filter, e.g. "level"
	filterCol string // SQL column to filter on, e.g. "level"
	orderBy   string // e.g. "ts ASC"
	key       string // JSON response key, e.g. "logs"
}

func makeLogHandler(cfg logHandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if logsDB == nil {
			http.Error(w, "Log database not available", http.StatusServiceUnavailable)
			return
		}
		var where []string
		var args []any
		if cfg.filter != "" {
			if v := r.URL.Query().Get(cfg.filter); v != "" {
				where, args = appendWhere(where, args, cfg.filterCol+" = ?", v)
			}
		}
		from, to := timeRangeFilter(r)
		where, args = appendTimeRange(where, args, from, to)
		limit, offset := paginateQuery(r)
		q := r.URL.Query().Get("q")
		if q != "" && cfg.ftsTable != "" {
			rows, total, err := queryFTS(logsDB, cfg.ftsTable, cfg.table, cfg.cols, q, where, args, limit, offset)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			respondLogs(w, r, cfg.key, rows, total, limit, offset)
			return
		}
		rows, total, err := queryLogTable(logsDB, cfg.table, cfg.cols, where, args, limit, offset, cfg.orderBy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondLogs(w, r, cfg.key, rows, total, limit, offset)
	}
}

// --- SQLite query helpers ---

// isPaginated returns true when the caller explicitly passed a limit param.
// Used to decide between raw-array response (legacy frontend) and wrapped {logs,total} response.
func isPaginated(r *http.Request) bool {
	return r.URL.Query().Get("limit") != ""
}

// paginateQuery extracts limit/offset from query params.
// Returns limit=0 when no limit param is given (caller should treat 0 as "no limit").
// When a limit param is present it is capped at 500.
func paginateQuery(r *http.Request) (limit, offset int) {
	if !isPaginated(r) {
		return 0, 0 // 0 = no limit; queryLogTable handles this
	}
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return
}

// respondLogs sends either a raw array (legacy) or a paginated wrapper depending on whether
// the caller passed a limit param.
func respondLogs(w http.ResponseWriter, r *http.Request, key string, rows []map[string]any, total, limit, offset int) {
	if !isPaginated(r) {
		respondJSON(w, rows)
		return
	}
	respondJSON(w, map[string]any{key: rows, "total": total, "limit": limit, "offset": offset})
}

// timeRangeFilter extracts from/to Unix nanosecond timestamps from query params.
func timeRangeFilter(r *http.Request) (from, to int64) {
	from, _ = strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	to, _ = strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	return
}

func appendWhere(where []string, args []any, clause string, vals ...any) ([]string, []any) {
	return append(where, clause), append(args, vals...)
}

func appendTimeRange(where []string, args []any, from, to int64) ([]string, []any) {
	if from > 0 {
		where, args = appendWhere(where, args, "ts >= ?", from)
	}
	if to > 0 {
		where, args = appendWhere(where, args, "ts <= ?", to)
	}
	return where, args
}

func buildWhereClause(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

// queryLogTable runs a parameterised SELECT with WHERE/ORDER/LIMIT/OFFSET and returns
// rows as []map[string]any plus the total count (capped at 100,001).
func queryLogTable(db *sql.DB, table, cols string, where []string, args []any, limit, offset int, orderBy string) ([]map[string]any, int, error) {
	wc := buildWhereClause(where)
	const countCap = 100_001
	var total int
	db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s%s LIMIT %d", table, wc, countCap), args...).Scan(&total)

	var q string
	if limit == 0 {
		q = fmt.Sprintf("SELECT %s FROM %s%s ORDER BY %s", cols, table, wc, orderBy)
	} else {
		q = fmt.Sprintf("SELECT %s FROM %s%s ORDER BY %s LIMIT %d OFFSET %d", cols, table, wc, orderBy, limit, offset)
	}
	sqlRows, err := db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer sqlRows.Close()
	rows, _, err := scanRows(sqlRows)
	return rows, total, err
}

// queryFTS runs an FTS5 match query joined to the content table, with optional extra WHERE filters.
func queryFTS(db *sql.DB, ftsTable, contentTable, cols, query string, where []string, args []any, limit, offset int) ([]map[string]any, int, error) {
	// Build qualified column list: "c.id, c.ts, c.level, ..."
	colList := make([]string, 0)
	for _, c := range strings.Split(cols, ",") {
		colList = append(colList, contentTable+"."+strings.TrimSpace(c))
	}
	qualifiedCols := strings.Join(colList, ", ")

	// FTS match uses the fts table alias in WHERE
	baseWhere := []string{ftsTable + " MATCH ?"}
	baseWhere = append(baseWhere, where...)
	ftsArgs := append([]any{query}, args...)
	wc := buildWhereClause(baseWhere)

	const countCap = 100_001
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM %s JOIN %s ON %s.rowid = %s.id%s LIMIT %d",
		ftsTable, contentTable, ftsTable, contentTable, wc, countCap)
	var total int
	db.QueryRow(countQ, ftsArgs...).Scan(&total)

	var q string
	if limit == 0 {
		q = fmt.Sprintf("SELECT %s FROM %s JOIN %s ON %s.rowid = %s.id%s ORDER BY %s.ts ASC",
			qualifiedCols, ftsTable, contentTable, ftsTable, contentTable, wc, contentTable)
	} else {
		q = fmt.Sprintf("SELECT %s FROM %s JOIN %s ON %s.rowid = %s.id%s ORDER BY %s.ts ASC LIMIT %d OFFSET %d",
			qualifiedCols, ftsTable, contentTable, ftsTable, contentTable, wc, contentTable, limit, offset)
	}
	sqlRows, err := db.Query(q, ftsArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer sqlRows.Close()
	rows, _, err := scanRows(sqlRows)
	return rows, total, err
}

// sqlColToJSON maps SQLite column names to the JSON field names the frontend expects
// (matching Go struct JSON tags from models.go).
var sqlColToJSON = map[string]string{
	"ts":            "Timestamp",
	"hostname":      "Hostname",
	"process":       "Process",
	"pid":           "PID",
	"level":         "Level",
	"message":       "Message",
	"source":        "Source",
	"line_number":   "LineNumber",
	"client_ip":     "Hostname", // nginx access: client IP stored in Hostname field
	"method":        "Process",  // nginx access: method stored in Process field
	"status_code":   "PID",      // nginx access: status stored in PID field
	"user":          "User",
	"event_type":    "EventType",
	"sudo_user":     "SudoUser",
	"command":       "Command",
	"source_ip":     "SourceIP",
	"session_id":    "SessionID",
	"from_version":  "FromVersion",
	"to_version":    "ToVersion",
	"service":       "Service",
	"version":       "Version",
	"thread_id":     "ThreadID",
	"task_name":     "TaskName",
	"duration_ms":   "DurationMS",
	"process_id":    "ProcessID",
	"protocol":      "Protocol",
	"event":         "Event",
	"appliance_id":  "ApplianceID",
	"appliance_ip":  "ApplianceIP",
	"appliance_host":"ApplianceHost",
	"category":      "Category",
	"severity":      "Severity",
	"description":   "Description",
	"info_json":     "InfoJSON",
	"synchronized":  "Synchronized",
	"replicated":    "Replicated",
	"source_type":   "SourceType",
	"source_id":     "SourceID",
	"content":       "Content",
	"message_type":  "MessageType",
	"is_multiline":  "IsMultiline",
	"raw_line":      "RawLine",
	"connection_id": "ConnectionID",
	"tid":           "TID",
	"client":        "Client",
	"server":        "Server",
	"request":       "Request",
	"upstream":      "Upstream",
	"host":          "Host",
	"referrer":      "Referrer",
}

func scanRows(sqlRows *sql.Rows) ([]map[string]any, int, error) {
	cols, err := sqlRows.Columns()
	if err != nil {
		return nil, 0, err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var rows []map[string]any
	for sqlRows.Next() {
		if err := sqlRows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(map[string]any, len(cols)*2)
		for i, col := range cols {
			val := vals[i]
			// ts: convert Unix nanoseconds to RFC3339 string, expose as both "ts",
			// "timestamp" (lowercase, newer views) and "Timestamp" (PascalCase, older views)
			if col == "ts" {
				if ns, ok := toInt64(val); ok && ns > 0 {
					iso := time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
					row["ts"] = ns
					row["timestamp"] = iso
					row["Timestamp"] = iso
				} else {
					row["ts"] = val
					row["timestamp"] = val
					row["Timestamp"] = val
				}
				continue
			}
			// Store under original snake_case name
			row[col] = val
			// Also store under PascalCase alias if one exists (for older frontend views)
			if alias, ok := sqlColToJSON[col]; ok {
				row[alias] = val
			}
		}
		rows = append(rows, row)
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	return rows, 0, sqlRows.Err()
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case []byte:
		var n int64
		fmt.Sscan(string(x), &n)
		return n, true
	}
	return 0, false
}

// countLogLevel queries a single level count from a table for overview stats.
func countLogLevel(table, levelCol string, levels []string) int {
	if logsDB == nil {
		return 0
	}
	placeholders := strings.Repeat("?,", len(levels))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(levels))
	for i, l := range levels {
		args[i] = l
	}
	var n int
	logsDB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s IN (%s)", table, levelCol, placeholders), args...).Scan(&n)
	return n
}

func countErrors() int {
	return countLogLevel("logs_syslog", "level", []string{"ERROR"}) +
		countLogLevel("logs_nginx_error", "level", []string{"ERROR"}) +
		countLogLevel("logs_auth", "level", []string{"ERROR"})
}

func countWarnings() int {
	return countLogLevel("logs_syslog", "level", []string{"WARNING"}) +
		countLogLevel("logs_nginx_error", "level", []string{"WARN"}) +
		countLogLevel("logs_auth", "level", []string{"WARNING"})
}

func countCritical() int {
	return countLogLevel("logs_syslog", "level", []string{"CRITICAL", "FATAL"}) +
		countLogLevel("logs_nginx_error", "level", []string{"CRIT", "EMERG"}) +
		countLogLevel("logs_auth", "level", []string{"CRITICAL", "FATAL"})
}

func getTopProcesses(n int) []models.Process {
	if len(archiveData.Processes) <= n {
		return archiveData.Processes
	}

	// Sort by CPU usage (descending)
	processes := make([]models.Process, len(archiveData.Processes))
	copy(processes, archiveData.Processes)

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].CPU > processes[j].CPU
	})

	return processes[:n]
}

// countTable returns the total row count for a log table (0 if DB unavailable).
func countTable(table string) int {
	if logsDB == nil {
		return 0
	}
	var n int
	logsDB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n
}

func getLogSummary() map[string]any {
	return map[string]any{
		"syslog_total": countTable("logs_syslog"),
		"nginx_total":  countTable("logs_nginx_error"),
		"auth_total":   countTable("logs_auth"),
		"by_level": map[string]int{
			"error":    countErrors(),
			"warning":  countWarnings(),
			"critical": countCritical(),
		},
	}
}

// detectAuthSecurityIssues analyzes auth logs for potential security concerns via SQLite.
func detectAuthSecurityIssues() []map[string]any {
	var issues []map[string]any
	if logsDB == nil {
		return issues
	}

	// Aggregate failed SSH attempts by source_ip
	rows, err := logsDB.Query(`SELECT source_ip, COUNT(*) FROM logs_auth WHERE event_type = ? AND source_ip != '' GROUP BY source_ip HAVING COUNT(*) > 5`, string(models.AuthEventSSHFailed))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip string
			var count int
			if rows.Scan(&ip, &count) == nil {
				issues = append(issues, map[string]any{
					"severity":  "WARNING",
					"source":    "auth",
					"title":     "Multiple failed SSH attempts from IP",
					"message":   fmt.Sprintf("IP %s had %d failed SSH attempts", ip, count),
					"source_ip": ip,
					"attempts":  count,
				})
			}
		}
	}

	// Aggregate failed auth attempts by user
	rows2, err := logsDB.Query(`SELECT user, COUNT(*) FROM logs_auth WHERE event_type IN (?,?) AND user != '' GROUP BY user HAVING COUNT(*) > 3`,
		string(models.AuthEventSSHFailed), string(models.AuthEventAuthFailure))
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var user string
			var count int
			if rows2.Scan(&user, &count) == nil {
				issues = append(issues, map[string]any{
					"severity": "WARNING",
					"source":   "auth",
					"title":    "Multiple failed authentication attempts for user",
					"message":  fmt.Sprintf("User %s had %d failed authentication attempts", user, count),
					"user":     user,
					"attempts": count,
				})
			}
		}
	}

	// Sudo escalations by non-root users
	rows3, err := logsDB.Query(`SELECT user, command, ts FROM logs_auth WHERE event_type = ? AND sudo_user = 'root' AND user != 'root'`,
		string(models.AuthEventSudo))
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var user, command string
			var ts int64
			if rows3.Scan(&user, &command, &ts) == nil {
				issues = append(issues, map[string]any{
					"severity":  "WARNING",
					"source":    "auth",
					"title":     "Non-root user executed sudo as root",
					"message":   fmt.Sprintf("User %s executed sudo command as root: %s", user, command),
					"user":      user,
					"command":   command,
					"timestamp": ts,
				})
			}
		}
	}

	return issues
}

// handleUnifiedLogs returns the merged cross-log timeline from logs_unified.
func handleUnifiedLogs(w http.ResponseWriter, r *http.Request) {
	if logsDB == nil {
		http.Error(w, "Log database not available", http.StatusServiceUnavailable)
		return
	}

	var where []string
	var args []any

	if sourceTypes := r.URL.Query().Get("source_type"); sourceTypes != "" {
		parts := strings.Split(sourceTypes, ",")
		placeholders := strings.Repeat("?,", len(parts))
		placeholders = placeholders[:len(placeholders)-1]
		clause := "source_type IN (" + placeholders + ")"
		pArgs := make([]any, len(parts))
		for i, p := range parts {
			pArgs[i] = strings.TrimSpace(p)
		}
		where, args = appendWhere(where, args, clause, pArgs...)
	}
	if level := r.URL.Query().Get("level"); level != "" {
		where, args = appendWhere(where, args, "level = ?", level)
	}
	from, to := timeRangeFilter(r)
	where, args = appendTimeRange(where, args, from, to)
	limit, offset := paginateQuery(r)
	q := r.URL.Query().Get("q")

	if q != "" {
		rows, total, err := queryFTS(logsDB, "fts_unified", "logs_unified",
			"id,ts,source_type,level,message,source_id",
			q, where, args, limit, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"rows": rows, "total": total, "limit": limit, "offset": offset})
		return
	}

	rows, total, err := queryLogTable(logsDB, "logs_unified",
		"id,ts,source_type,level,message,source_id",
		where, args, limit, offset, "ts ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, map[string]any{"rows": rows, "total": total, "limit": limit, "offset": offset})
}

// handleGraphs serves system and network utilization graph PNG files
func handleGraphs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Extract path from URL: /api/graphs/{type}/{filename}
	// Examples:
	//   /api/graphs/interface_port1.rrd-daily.png (network interface)
	//   /api/graphs/cpu-daily.png (CPU)
	//   /api/graphs/ram-used-daily.png (RAM)
	//   /api/graphs/disk-used-daily.png (Disk)
	pathParts := strings.TrimPrefix(r.URL.Path, "/api/graphs/")

	// Security: validate path to prevent path traversal attacks
	if strings.Contains(pathParts, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Only allow .png files
	if !strings.HasSuffix(pathParts, ".png") {
		http.Error(w, "Only PNG files are allowed", http.StatusBadRequest)
		return
	}

	// Get base directory from archive metadata
	baseDir := archiveData.Metadata.ExtractedPath

	// Determine subdirectory based on filename pattern
	var graphPath string
	filename := filepath.Base(pathParts)

	if strings.HasPrefix(filename, "cpu-") {
		// CPU graphs: health_check/stats/cpu/cpu-{daily,weekly,monthly}.png
		graphPath = filepath.Join(baseDir, "health_check", "stats", "cpu", filename)
	} else if strings.HasPrefix(filename, "ram-") {
		// RAM graphs: health_check/stats/ram/ram-used-{daily,weekly,monthly}.png
		graphPath = filepath.Join(baseDir, "health_check", "stats", "ram", filename)
	} else if strings.HasPrefix(filename, "disk-") {
		// Disk graphs: health_check/stats/disk/disk-used-{daily,weekly,monthly}.png
		graphPath = filepath.Join(baseDir, "health_check", "stats", "disk", filename)
	} else if strings.HasPrefix(filename, "interface_") {
		// Network interface graphs: health_check/stats/net_interfaces/interface_{name}.rrd-{period}.png
		graphPath = filepath.Join(baseDir, "health_check", "stats", "net_interfaces", filename)
	} else if strings.HasPrefix(filename, "sync-bytes-") {
		// Appliance sync throughput graphs: health_check/stats/appliances_sync/sync-bytes-{period}.png
		graphPath = filepath.Join(baseDir, "health_check", "stats", "appliances_sync", filename)
	} else {
		http.Error(w, "Unknown graph type", http.StatusBadRequest)
		return
	}

	// Check if file exists
	if _, err := os.Stat(graphPath); os.IsNotExist(err) {
		http.Error(w, "Graph not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, graphPath)
}

// handleOutputAnalysisCheck checks if the output_analysis.out file exists
func handleOutputAnalysisCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}

	// Construct path to output_analysis.out
	baseDir := archiveData.Metadata.ExtractedPath
	outputPath := filepath.Join(baseDir, "health_check", "log_analysis", "output_analysis.out")

	// Check if file exists
	_, err := os.Stat(outputPath)
	exists := err == nil

	respondJSON(w, map[string]bool{"exists": exists})
}

// handleGoAccessCheck checks if the goaccess-out.html file exists
func handleGoAccessCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}

	// Construct path to goaccess-out.html
	baseDir := archiveData.Metadata.ExtractedPath
	goAccessPath := filepath.Join(baseDir, "health_check", "log_analysis", "goaccess-out.html")

	// Check if file exists
	_, err := os.Stat(goAccessPath)
	exists := err == nil

	respondJSON(w, map[string]bool{"exists": exists})
}

// handleInterfaceGraphsCheck checks which interfaces have utilization graphs available
func handleInterfaceGraphsCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]interface{}{"interfaces": []string{}})
		return
	}

	// Get the interface name from query parameter
	interfaceName := r.URL.Query().Get("interface")
	if interfaceName == "" {
		http.Error(w, "interface parameter required", http.StatusBadRequest)
		return
	}

	// Check if at least one graph file exists for this interface (daily)
	baseDir := archiveData.Metadata.ExtractedPath
	graphPath := filepath.Join(baseDir, "health_check", "stats", "net_interfaces",
		fmt.Sprintf("interface_%s.rrd-daily.png", interfaceName))

	_, err := os.Stat(graphPath)
	exists := err == nil

	respondJSON(w, map[string]bool{"exists": exists})
}

// handleOutputAnalysis serves the raw output_analysis.out file
func handleOutputAnalysis(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Construct path to output_analysis.out
	baseDir := archiveData.Metadata.ExtractedPath
	outputPath := filepath.Join(baseDir, "health_check", "log_analysis", "output_analysis.out")

	// Check if file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		http.Error(w, "Output analysis file not found", http.StatusNotFound)
		return
	}

	// Read the file content
	content, err := os.ReadFile(outputPath)
	if err != nil {
		http.Error(w, "Error reading output analysis file", http.StatusInternalServerError)
		return
	}

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

// handleGoAccess serves the goaccess-out.html file
func handleGoAccess(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Construct path to goaccess-out.html
	baseDir := archiveData.Metadata.ExtractedPath
	goAccessPath := filepath.Join(baseDir, "health_check", "log_analysis", "goaccess-out.html")

	// Check if file exists
	if _, err := os.Stat(goAccessPath); os.IsNotExist(err) {
		http.Error(w, "GoAccess report not found", http.StatusNotFound)
		return
	}

	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Serve the HTML file
	http.ServeFile(w, r, goAccessPath)
}

// handlePostAnalysisCheck checks if post_analysis.html exists
func handlePostAnalysisCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}

	baseDir := archiveData.Metadata.ExtractedPath
	postAnalysisPath := filepath.Join(baseDir, "health_check", "log_analysis", "post_analysis.html")

	_, err := os.Stat(postAnalysisPath)
	respondJSON(w, map[string]bool{"exists": err == nil})
}

// handlePostAnalysis serves the post_analysis.html file
func handlePostAnalysis(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	baseDir := archiveData.Metadata.ExtractedPath
	postAnalysisPath := filepath.Join(baseDir, "health_check", "log_analysis", "post_analysis.html")

	if _, err := os.Stat(postAnalysisPath); os.IsNotExist(err) {
		http.Error(w, "Post analysis report not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, postAnalysisPath)
}

// handleSaveNotes saves markdown notes to penny_note.md in the archive folder
func handleSaveNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse JSON request
	var request struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get archive folder path
	folderPath := archiveData.Metadata.ExtractedPath
	if folderPath == "" {
		http.Error(w, "Archive folder path not available", http.StatusInternalServerError)
		return
	}

	// Create file path
	notesPath := filepath.Join(folderPath, "penny_note.md")

	// Write notes to file
	if err := os.WriteFile(notesPath, []byte(request.Content), 0644); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save notes: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success response
	respondJSON(w, map[string]string{"status": "saved"})
}

// handleLoadNotes loads markdown notes from penny_note.md in the archive folder
func handleLoadNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	// Get archive folder path
	folderPath := archiveData.Metadata.ExtractedPath
	if folderPath == "" {
		http.Error(w, "Archive folder path not available", http.StatusInternalServerError)
		return
	}

	// Create file path
	notesPath := filepath.Join(folderPath, "penny_note.md")

	// Check if file exists
	content, err := os.ReadFile(notesPath)
	if os.IsNotExist(err) {
		// File doesn't exist yet, return empty content
		respondJSON(w, map[string]string{"content": ""})
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load notes: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the content
	respondJSON(w, map[string]string{"content": string(content)})
}

// handleHCDisksCheck checks if hc_disks output is available
func handleHCDisksCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}
	respondJSON(w, map[string]bool{"exists": archiveData.HCDisks != ""})
}

// handleHCDisks returns the output of hc_disks.sh
func handleHCDisks(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil || archiveData.HCDisks == "" {
		http.Error(w, "HC Disks output not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(archiveData.HCDisks))
}

// handleHCUpgradePathCheck checks if hc_upgrade_path output is available
func handleHCUpgradePathCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}
	respondJSON(w, map[string]bool{"exists": archiveData.HCUpgradePath != ""})
}

// handleHCUpgradePath returns the output of hc_upgrade_path.sh
func handleHCUpgradePath(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil || archiveData.HCUpgradePath == "" {
		http.Error(w, "HC Upgrade Path output not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(archiveData.HCUpgradePath))
}

// handleSettingsLoad returns current penny.yaml values plus per-script status checks
func handleSettingsLoad(w http.ResponseWriter, r *http.Request) {
	type byosEntry struct {
		Name       string `json:"name"`
		Tag        string `json:"tag"`
		Path       string `json:"path"`
		Found      bool   `json:"found"`
		Executable bool   `json:"executable"`
	}
	type response struct {
		FileExists bool        `json:"fileExists"`
		Landing    string      `json:"landing"`
		Theme      string      `json:"theme"`
		DebugKI    bool        `json:"debugKI"`
		Byos       []byosEntry `json:"byos"`
	}

	cfg, err := pennyconfig.Load()
	if err != nil || cfg == nil {
		respondJSON(w, response{FileExists: false, Landing: "system", Theme: "light", Byos: []byosEntry{}})
		return
	}

	entries := make([]byosEntry, 0, len(cfg.Byos))
	for _, s := range cfg.Byos {
		status := pennyconfig.CheckScript(s)
		entries = append(entries, byosEntry{
			Name: s.Name, Tag: s.Tag, Path: s.Path,
			Found: status.Found, Executable: status.Executable,
		})
	}

	landing := cfg.Landing
	if landing == "" {
		landing = "system"
	}
	theme := cfg.Theme
	if theme == "" {
		theme = "light"
	}

	respondJSON(w, response{FileExists: true, Landing: landing, Theme: theme, DebugKI: cfg.DebugKI, Byos: entries})
}

// handleSettingsSave writes submitted settings to ~/.penny/penny.yaml
func handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Landing string `json:"landing"`
		Theme   string `json:"theme"`
		DebugKI bool   `json:"debugKI"`
		Byos    []struct {
			Name string `json:"name"`
			Tag  string `json:"tag"`
			Path string `json:"path"`
		} `json:"byos"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Theme != "dark" && req.Theme != "light" {
		req.Theme = "light"
	}
	if req.Landing == "" {
		req.Landing = "system"
	}

	cfg := &pennyconfig.Config{
		Landing: req.Landing,
		Theme:   req.Theme,
		DebugKI: req.DebugKI,
	}
	for _, s := range req.Byos {
		cfg.Byos = append(cfg.Byos, pennyconfig.Script{Name: s.Name, Tag: s.Tag, Path: s.Path})
	}

	if err := pennyconfig.Save(cfg); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save settings: %v", err), http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]string{"status": "saved"})
}

// handlePennyConfig returns user preferences (theme, landing) for the frontend
func handlePennyConfig(w http.ResponseWriter, r *http.Request) {
	theme := "light"
	landing := "system"
	if archiveData != nil {
		if archiveData.Theme != "" {
			theme = archiveData.Theme
		}
		if archiveData.LandingView != "" {
			landing = archiveData.LandingView
		}
	}
	respondJSON(w, map[string]string{"theme": theme, "landing": landing})
}

// handleByosCheck returns whether any BYOS results are available
func handleByosCheck(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		respondJSON(w, map[string]bool{"exists": false})
		return
	}
	respondJSON(w, map[string]bool{"exists": len(archiveData.ByosResults) > 0})
}

// handleByos returns all BYOS results as JSON
func handleByos(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil || len(archiveData.ByosResults) == 0 {
		http.Error(w, "No BYOS results available", http.StatusNotFound)
		return
	}
	respondJSON(w, archiveData.ByosResults)
}

func handleHighscore(w http.ResponseWriter, r *http.Request) {
	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, "cannot determine home directory", http.StatusInternalServerError)
		return
	}
	pennyDir := filepath.Join(home, ".penny")

	// Check .penny exists — if not, signal unavailable without creating it
	if _, err := os.Stat(pennyDir); os.IsNotExist(err) {
		if r.Method == http.MethodGet {
			respondJSON(w, map[string]interface{}{"exists": false})
		} else {
			http.Error(w, ".penny directory does not exist", http.StatusNotFound)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Find the single hs_* file (there should only ever be one)
		entries, err := os.ReadDir(pennyDir)
		if err != nil {
			http.Error(w, "cannot read .penny directory", http.StatusInternalServerError)
			return
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "hs_") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(pennyDir, e.Name()))
			if err != nil {
				continue
			}
			score, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
			if err != nil {
				continue
			}
			respondJSON(w, map[string]interface{}{"exists": true, "score": score})
			return
		}
		respondJSON(w, map[string]interface{}{"exists": false})

	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var req struct {
			Score int64 `json:"score"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// Read existing best score
		entries, _ := os.ReadDir(pennyDir)
		var bestScore int64 = -1
		var bestFile string
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "hs_") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(pennyDir, e.Name()))
			if err != nil {
				continue
			}
			s, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
			if err != nil {
				continue
			}
			if s > bestScore {
				bestScore = s
				bestFile = e.Name()
			}
		}

		if req.Score <= bestScore {
			// Not a new record — nothing to write
			respondJSON(w, map[string]interface{}{"saved": false, "highscore": bestScore})
			return
		}

		// Write new record file
		newName := fmt.Sprintf("hs_%d", time.Now().Unix())
		if err := os.WriteFile(filepath.Join(pennyDir, newName), []byte(strconv.FormatInt(req.Score, 10)), 0644); err != nil {
			http.Error(w, "failed to write highscore", http.StatusInternalServerError)
			return
		}

		// Remove old best file (and any other stale hs_* files)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "hs_") && e.Name() != newName {
				_ = os.Remove(filepath.Join(pennyDir, e.Name()))
			}
		}
		_ = bestFile // referenced above for clarity

		respondJSON(w, map[string]interface{}{"saved": true, "highscore": req.Score})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
