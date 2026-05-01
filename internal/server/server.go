package server

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"penny/internal/models"
)

//go:embed static/*
var staticFiles embed.FS

// StartBackup starts the HTTP server in backup mode, serving db-backup.html at /
func StartBackup(port int, pennyVersion string) error {
	SetPennyVersion(pennyVersion)

	// Backup API
	http.HandleFunc("/api/backup", handleBackupData)
	http.HandleFunc("/api/backup/table", handleBackupTable)
	http.HandleFunc("/api/version", handleVersion)

	// Settings API
	http.HandleFunc("/api/settings-load", handleSettingsLoad)
	http.HandleFunc("/api/settings-save", handleSettingsSave)
	http.HandleFunc("/api/penny-config", handlePennyConfig)

	// Settings page
	http.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		f, err := staticFiles.Open("static/index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		http.ServeContent(w, r, "index.html", stat.ModTime(), f.(io.ReadSeeker))
	})

	// Serve db-backup.html for all page routes
	dbBackupHandler := func(w http.ResponseWriter, r *http.Request) {
		f, err := staticFiles.Open("static/db-backup.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		http.ServeContent(w, r, "db-backup.html", stat.ModTime(), f.(io.ReadSeeker))
	}
	http.HandleFunc("/", dbBackupHandler)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Server listening on http://localhost%s\n", addr)
	return http.ListenAndServe(addr, nil)
}

// Start starts the HTTP server
func Start(port int, data *models.ArchiveData, pennyVersion string) error {
	// Set the archive data for handlers
	SetArchiveData(data)
	SetPennyVersion(pennyVersion)

	// Serve embedded static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	// API routes
	http.HandleFunc("/api/metadata", handleMetadata)
	http.HandleFunc("/api/system", handleSystemInfo)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/processes", handleProcesses)
	http.HandleFunc("/api/network", handleNetwork)
	http.HandleFunc("/api/bpf-stats", handleBPFStats)
	http.HandleFunc("/api/graphs/", handleGraphs)
	http.HandleFunc("/api/storage", handleStorage)
	http.HandleFunc("/api/overview", handleOverview)
	http.HandleFunc("/api/dashboard", handleDashboard)
	http.HandleFunc("/api/n2os-config", handleN2OSConfig)
	http.HandleFunc("/api/n2op-logs", handleN2OpLogs)
	http.HandleFunc("/api/n2osjobs-logs", handleN2OSJobLogs)
	http.HandleFunc("/api/n2osjobs-di-logs", handleN2OSJobDILogs)
	http.HandleFunc("/api/n2osdelayedjobs-logs", handleN2OSDelayedJobLogs)
	http.HandleFunc("/api/n2osmigrate-logs", handleN2OSMigrateLogs)
	stdCols := "id,ts,process_id,thread_id,level,message,source,line_number,raw_line"
	evtCols := "id,ts,process_id,thread_id,event,source,line_number,raw_line"
	http.HandleFunc("/api/n2osids-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_ids", ftsTable: "fts_n2os_ids", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osidsevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_ids_events", filter: "protocol", filterCol: "protocol",
		cols: "id,ts,process_id,thread_id,protocol,event,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2ostrace-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_trace", ftsTable: "fts_n2os_trace", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2ostraceevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_trace_events", cols: evtCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2ossandbox-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_sandbox", ftsTable: "fts_n2os_sandbox", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2ossandboxevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_sandbox_events", cols: evtCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osreverse-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_reverse", ftsTable: "fts_n2os_reverse", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osreverseevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_reverse_events", cols: evtCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osva-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_va", ftsTable: "fts_n2os_va", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osvaevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_va_events", cols: evtCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osstixdb-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_stixdb", ftsTable: "fts_n2os_stixdb",
		cols: "id,ts,message,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osstrategist-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_strategist", ftsTable: "fts_n2os_strategist", filter: "level", filterCol: "level",
		cols: "id,ts,level,component,message,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2ossp-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2ossp", ftsTable: "fts_n2ossp", filter: "level", filterCol: "level",
		cols: "id,ts,level,pid,message,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/puma-logs", makeLogHandler(logHandlerConfig{
		table: "logs_puma", ftsTable: "fts_puma", filter: "level", filterCol: "level",
		cols: "id,ts,pid,level,message,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/puma-err-logs", makeLogHandler(logHandlerConfig{
		table: "logs_puma_err", cols: "id,ts,message,source,line_number,raw_line",
		orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2oscpe2cve-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_cpe2cve", ftsTable: "fts_n2os_cpe2cve",
		cols: "id,ts,message,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osotelcol-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_otelcol", ftsTable: "fts_n2os_otelcol", filter: "level", filterCol: "level",
		cols: "id,ts,level,caller,message,fields,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osrc-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_rc", ftsTable: "fts_n2os_rc", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osrcevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_rc_events", cols: evtCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osalert-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_alert", ftsTable: "fts_n2os_alert", filter: "level", filterCol: "level",
		cols: stdCols, orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osalertevents-logs", makeLogHandler(logHandlerConfig{
		table: "logs_n2os_alert_events", filter: "event_type", filterCol: "event_type",
		cols: "id,ts,process_id,thread_id,event_type,event,source,line_number,raw_line", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/n2osproduction-logs", makeLogHandler(logHandlerConfig{
		table: "logs_production", ftsTable: "fts_production", filter: "level", filterCol: "level",
		cols: "id,ts,process_id,level,message,source,line_number", orderBy: "ts ASC", key: "logs",
	}))
	http.HandleFunc("/api/health-events", handleHealthEvents)
	http.HandleFunc("/api/auth-logs", handleAuthLogs)
	http.HandleFunc("/api/logs/unified", handleUnifiedLogs)
	http.HandleFunc("/api/database", handleDatabase)
	http.HandleFunc("/api/database/sampledata", handleDatabaseSampleData)
	http.HandleFunc("/api/appliances", handleAppliances)
	http.HandleFunc("/api/n2os-conf", handleN2OSConf)
	http.HandleFunc("/api/output-analysis-check", handleOutputAnalysisCheck)
	http.HandleFunc("/api/output-analysis", handleOutputAnalysis)
	http.HandleFunc("/api/goaccess-check", handleGoAccessCheck)
	http.HandleFunc("/api/goaccess", handleGoAccess)
	http.HandleFunc("/api/post-analysis-check", handlePostAnalysisCheck)
	http.HandleFunc("/api/post-analysis", handlePostAnalysis)
	http.HandleFunc("/api/hc-upgrade-path-check", handleHCUpgradePathCheck)
	http.HandleFunc("/api/hc-upgrade-path", handleHCUpgradePath)
	http.HandleFunc("/api/hc-disks-check", handleHCDisksCheck)
	http.HandleFunc("/api/hc-disks", handleHCDisks)
	http.HandleFunc("/api/settings-load", handleSettingsLoad)
	http.HandleFunc("/api/settings-save", handleSettingsSave)
	http.HandleFunc("/api/penny-config", handlePennyConfig)
	http.HandleFunc("/api/version", handleVersion)
	http.HandleFunc("/api/byos-check", handleByosCheck)
	http.HandleFunc("/api/byos", handleByos)
	http.HandleFunc("/api/interface-graphs-check", handleInterfaceGraphsCheck)
	http.HandleFunc("/api/save-notes", handleSaveNotes)
	http.HandleFunc("/api/load-notes", handleLoadNotes)

	// Backup API
	http.HandleFunc("/api/backup", handleBackupData)
	http.HandleFunc("/api/backup/table", handleBackupTable)

	// Backup page — serve db-backup.html directly so /db-backup is a real URL
	http.HandleFunc("/db-backup", func(w http.ResponseWriter, r *http.Request) {
		f, err := staticFiles.Open("static/db-backup.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		http.ServeContent(w, r, "db-backup.html", stat.ModTime(), f.(io.ReadSeeker))
	})

	// Settings page — serve index.html directly so /settings is a real URL
	http.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		f, err := staticFiles.Open("static/index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		http.ServeContent(w, r, "index.html", stat.ModTime(), f.(io.ReadSeeker))
	})

	// Serve static files (dashboard UI)
	http.Handle("/", http.FileServer(http.FS(staticFS)))

	// Start server
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Server listening on http://localhost%s\n", addr)

	return http.ListenAndServe(addr, nil)
}
