package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"penny/internal/models"
	"sort"
	"strings"
)

var archiveData *models.ArchiveData

// SetArchiveData sets the parsed archive data for handlers to use
func SetArchiveData(data *models.ArchiveData) {
	archiveData = data
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

// handleLogs returns log entries with optional filtering
func handleLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	logType := r.URL.Query().Get("type")
	level := r.URL.Query().Get("level")
	eventType := r.URL.Query().Get("event_type")
	authUser := r.URL.Query().Get("auth_user")
	sourceIP := r.URL.Query().Get("source_ip")

	var result interface{}

	switch logType {
	case "nginx":
		logs := archiveData.Logs.NginxErrors
		if level != "" {
			logs = filterNginxByLevel(logs, level)
		}
		result = logs
	case "nginx-access":
		logs := archiveData.Logs.NginxAccess
		if level != "" {
			logs = filterSyslogByLevel(logs, level)
		}
		result = logs
	case "auth":
		logs := archiveData.Logs.AuthLog
		if eventType != "" {
			logs = filterAuthByEventType(logs, eventType)
		}
		if authUser != "" {
			logs = filterAuthByUser(logs, authUser)
		}
		if sourceIP != "" {
			logs = filterAuthBySourceIP(logs, sourceIP)
		}
		if level != "" {
			logs = filterAuthByLevel(logs, level)
		}
		result = logs
	case "messages", "syslog", "":
		logs := archiveData.Logs.Messages
		if level != "" {
			logs = filterSyslogByLevel(logs, level)
		}
		result = logs
	default:
		http.Error(w, "Invalid log type", http.StatusBadRequest)
		return
	}

	respondJSON(w, result)
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

// handleN2OpLogs returns N2OS operation logs with optional filtering and pagination
func handleN2OpLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	eventType := r.URL.Query().Get("event_type")
	logs := archiveData.N2OpLogs

	// Filter by event type if specified
	if eventType != "" {
		var filtered []models.N2OpLogEntry
		for _, log := range logs {
			if string(log.EventType) == eventType {
				filtered = append(filtered, log)
			}
		}
		logs = filtered
	}

	respondJSON(w, map[string]interface{}{
		"logs":       logs,
		"violations": archiveData.UpgradeViolations,
	})
}

// handleN2OSJobLogs returns N2OS job logs (background tasks)
func handleN2OSJobLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSJobLogs)
}

// handleN2OSMigrateLogs returns N2OS migration logs
func handleN2OSMigrateLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, map[string]interface{}{
		"summary": archiveData.N2OSMigrateSummary,
		"entries": archiveData.N2OSMigrateLogs,
	})
}

// handleN2OSIDSLogs returns N2OS IDS logs
func handleN2OSIDSLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSIDSLogs)
}

// handleN2OSIDSEventsLogs returns N2OS IDS events logs
func handleN2OSIDSEventsLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSIDSEventsLogs)
}

// handleN2OSAlertLogs returns N2OS alert logs
func handleN2OSAlertLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSAlertLogs)
}

// handleN2OSAlertEventsLogs returns N2OS alert events logs
func handleN2OSAlertEventsLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSAlertEventsLogs)
}

// handleN2OSProductionLogs returns N2OS production logs
func handleN2OSProductionLogs(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	respondJSON(w, archiveData.N2OSProductionLogs)
}

// handleHealthEvents returns health events with optional filtering
func handleHealthEvents(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	category := r.URL.Query().Get("category")
	eventType := r.URL.Query().Get("event_type")
	severity := r.URL.Query().Get("severity")
	appliance := r.URL.Query().Get("appliance")

	events := archiveData.HealthEvents

	// Filter by category if specified
	if category != "" {
		var filtered []models.HealthEvent
		for _, event := range events {
			if string(event.Category) == category {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// Filter by event type if specified
	if eventType != "" {
		var filtered []models.HealthEvent
		for _, event := range events {
			if string(event.EventType) == eventType {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// Filter by severity if specified
	if severity != "" {
		var filtered []models.HealthEvent
		for _, event := range events {
			if string(event.Severity) == severity {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// Filter by appliance hostname if specified
	if appliance != "" {
		var filtered []models.HealthEvent
		for _, event := range events {
			if strings.Contains(strings.ToLower(event.ApplianceHost), strings.ToLower(appliance)) {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	respondJSON(w, events)
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

	overview := map[string]interface{}{
		"metadata":        archiveData.Metadata,
		"system_info":     archiveData.SystemInfo,
		"total_logs":      len(archiveData.Logs.Messages) + len(archiveData.Logs.NginxErrors) + len(archiveData.Logs.AuthLog),
		"total_processes": len(archiveData.Processes),
		"error_count":     countErrors(),
		"warning_count":   countWarnings(),
		"critical_count":  countCritical(),
		"top_processes":   getTopProcesses(10),
		"log_summary":     getLogSummary(),
	}

	respondJSON(w, overview)
}

// handleIssues returns detected issues (placeholder for future detection)
func handleIssues(w http.ResponseWriter, r *http.Request) {
	if archiveData == nil {
		http.Error(w, "No data loaded", http.StatusInternalServerError)
		return
	}

	issues := []map[string]interface{}{}

	// Check ZFS pool health
	for _, pool := range archiveData.Storage.ZpoolStatus {
		if pool.State == "DEGRADED" || pool.State == "FAULTED" || pool.State == "UNAVAIL" {
			severity := "CRITICAL"
			if pool.State == "DEGRADED" {
				severity = "WARNING"
			}

			issue := map[string]interface{}{
				"severity":    severity,
				"source":      "zpool",
				"title":       "ZFS Pool " + pool.Pool + " is " + pool.State,
				"description": pool.Status,
				"pool_name":   pool.Pool,
				"pool_state":  pool.State,
				"errors":      pool.Errors,
			}

			// Check for data corruption
			if strings.Contains(strings.ToLower(pool.Status), "corruption") ||
				strings.Contains(strings.ToLower(pool.Errors), "permanent errors") {
				issue["severity"] = "CRITICAL"
				issue["data_corruption"] = true
			}

			issues = append(issues, issue)
		}
	}

	// Check syslog for errors
	for _, log := range archiveData.Logs.Messages {
		if log.Level == "ERROR" || log.Level == "CRITICAL" || log.Level == "FATAL" {
			issues = append(issues, map[string]interface{}{
				"severity":  log.Level,
				"source":    "syslog",
				"process":   log.Process,
				"message":   log.Message,
				"timestamp": log.Timestamp,
			})
		}
	}

	// Check nginx for critical errors
	for _, log := range archiveData.Logs.NginxErrors {
		if log.Level == "CRIT" || log.Level == "EMERG" || log.Level == "ALERT" {
			issues = append(issues, map[string]interface{}{
				"severity":  log.Level,
				"source":    "nginx",
				"message":   log.Message,
				"timestamp": log.Timestamp,
			})
		}
	}

	// Check auth logs for security issues
	issues = append(issues, detectAuthSecurityIssues()...)

	// Check database for issues (oversized tables and vacuum needs)
	for _, table := range archiveData.Database.Tables {
		if table.IsOversized {
			issues = append(issues, map[string]interface{}{
				"severity":    "WARNING",
				"source":      "database",
				"title":       "Database table exceeds 1 GB",
				"table_name":  table.TableName,
				"size":        table.Size,
				"description": fmt.Sprintf("Table '%s' is %s in size, which may impact performance", table.TableName, table.Size),
			})
		}
		if table.NeedsVacuum {
			issues = append(issues, map[string]interface{}{
				"severity":    "WARNING",
				"source":      "database",
				"title":       "Database table needs vacuum",
				"table_name":  table.TableName,
				"dead_tuples": table.DeadTuples,
				"threshold":   table.AutovacuumThreshold,
				"description": fmt.Sprintf("Table '%s' has %d dead tuples (threshold: %d)", table.TableName, table.DeadTuples, table.AutovacuumThreshold),
			})
		}
	}

	// Check BPF statistics for packet capture issues
	for _, comp := range archiveData.BPFComparisons {
		// Flag interfaces with packet drops
		if comp.DropDelta > 0 {
			severity := "WARNING"
			if comp.DropPercentage > 1.0 { // More than 1% drop rate
				severity = "CRITICAL"
			}

			issues = append(issues, map[string]interface{}{
				"severity":        severity,
				"source":          "bpf",
				"title":           fmt.Sprintf("Packet drops detected on %s", comp.Interface),
				"interface":       comp.Interface,
				"process":         comp.Command,
				"pid":             comp.PID,
				"drops":           comp.DropDelta,
				"drop_rate":       fmt.Sprintf("%.2f pkt/s", comp.DropRate),
				"drop_percentage": fmt.Sprintf("%.2f%%", comp.DropPercentage),
				"description":     fmt.Sprintf("Interface %s (PID %d, %s) dropped %d packets (%.2f%%) at %.2f pkt/s", comp.Interface, comp.PID, comp.Command, comp.DropDelta, comp.DropPercentage, comp.DropRate),
			})
		}

		// Flag interfaces with significant buffer growth (potential backpressure)
		if comp.BufferGrowth > 200 { // More than 200% growth
			severity := "WARNING"
			if comp.BufferGrowth > 500 { // More than 500% growth is critical
				severity = "CRITICAL"
			}

			issues = append(issues, map[string]interface{}{
				"severity":      severity,
				"source":        "bpf",
				"title":         fmt.Sprintf("High buffer growth on %s", comp.Interface),
				"interface":     comp.Interface,
				"process":       comp.Command,
				"pid":           comp.PID,
				"buffer_growth": fmt.Sprintf("%.0f%%", comp.BufferGrowth),
				"recv_rate":     fmt.Sprintf("%.2f pkt/s", comp.RecvRate),
				"description":   fmt.Sprintf("Interface %s (PID %d, %s) has %s buffer growth at %.2f pkt/s receive rate", comp.Interface, comp.PID, comp.Command, fmt.Sprintf("%.0f%%", comp.BufferGrowth), comp.RecvRate),
			})
		}
	}

	// Sort by severity and timestamp
	sort.Slice(issues, func(i, j int) bool {
		// Prioritize CRITICAL over others
		sevI := issues[i]["severity"].(string)
		sevJ := issues[j]["severity"].(string)
		if sevI == "CRITICAL" && sevJ != "CRITICAL" {
			return true
		}
		if sevI != "CRITICAL" && sevJ == "CRITICAL" {
			return false
		}
		// Then by timestamp if available
		if tsI, okI := issues[i]["timestamp"]; okI {
			if tsJ, okJ := issues[j]["timestamp"]; okJ {
				ti, _ := tsI.(string)
				tj, _ := tsJ.(string)
				return ti > tj
			}
		}
		return false
	})

	respondJSON(w, issues)
}

// Helper functions

func filterSyslogByLevel(logs []models.LogEntry, level string) []models.LogEntry {
	var filtered []models.LogEntry
	for _, log := range logs {
		if strings.EqualFold(log.Level, level) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func filterNginxByLevel(logs []models.NginxLogEntry, level string) []models.NginxLogEntry {
	var filtered []models.NginxLogEntry
	for _, log := range logs {
		if strings.EqualFold(log.Level, level) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func filterAuthByEventType(logs []models.AuthLogEntry, eventType string) []models.AuthLogEntry {
	var filtered []models.AuthLogEntry
	for _, log := range logs {
		if string(log.EventType) == eventType {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func filterAuthByUser(logs []models.AuthLogEntry, user string) []models.AuthLogEntry {
	var filtered []models.AuthLogEntry
	for _, log := range logs {
		if strings.Contains(strings.ToLower(log.User), strings.ToLower(user)) ||
			strings.Contains(strings.ToLower(log.SudoUser), strings.ToLower(user)) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func filterAuthBySourceIP(logs []models.AuthLogEntry, sourceIP string) []models.AuthLogEntry {
	var filtered []models.AuthLogEntry
	for _, log := range logs {
		if strings.Contains(log.SourceIP, sourceIP) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func filterAuthByLevel(logs []models.AuthLogEntry, level string) []models.AuthLogEntry {
	var filtered []models.AuthLogEntry
	for _, log := range logs {
		if strings.EqualFold(log.Level, level) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

func countErrors() int {
	count := 0
	for _, log := range archiveData.Logs.Messages {
		if log.Level == "ERROR" {
			count++
		}
	}
	for _, log := range archiveData.Logs.NginxErrors {
		if log.Level == "ERROR" {
			count++
		}
	}
	for _, log := range archiveData.Logs.AuthLog {
		if log.Level == "ERROR" {
			count++
		}
	}
	return count
}

func countWarnings() int {
	count := 0
	for _, log := range archiveData.Logs.Messages {
		if log.Level == "WARNING" {
			count++
		}
	}
	for _, log := range archiveData.Logs.NginxErrors {
		if log.Level == "WARN" {
			count++
		}
	}
	for _, log := range archiveData.Logs.AuthLog {
		if log.Level == "WARNING" {
			count++
		}
	}
	return count
}

func countCritical() int {
	count := 0
	for _, log := range archiveData.Logs.Messages {
		if log.Level == "CRITICAL" || log.Level == "FATAL" {
			count++
		}
	}
	for _, log := range archiveData.Logs.NginxErrors {
		if log.Level == "CRIT" || log.Level == "EMERG" {
			count++
		}
	}
	for _, log := range archiveData.Logs.AuthLog {
		if log.Level == "CRITICAL" || log.Level == "FATAL" {
			count++
		}
	}
	return count
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

func getLogSummary() map[string]interface{} {
	return map[string]interface{}{
		"syslog_total": len(archiveData.Logs.Messages),
		"nginx_total":  len(archiveData.Logs.NginxErrors),
		"auth_total":   len(archiveData.Logs.AuthLog),
		"by_level": map[string]int{
			"error":    countErrors(),
			"warning":  countWarnings(),
			"critical": countCritical(),
		},
	}
}

// detectAuthSecurityIssues analyzes auth logs for potential security concerns
func detectAuthSecurityIssues() []map[string]interface{} {
	var issues []map[string]interface{}

	failedAttempts := make(map[string]int) // IP -> count
	failedUsers := make(map[string]int)    // User -> count

	for _, log := range archiveData.Logs.AuthLog {
		// Count failed SSH attempts by IP
		if log.EventType == models.AuthEventSSHFailed && log.SourceIP != "" {
			failedAttempts[log.SourceIP]++
		}

		// Count failed authentication attempts by user
		if (log.EventType == models.AuthEventSSHFailed || log.EventType == models.AuthEventAuthFailure) && log.User != "" {
			failedUsers[log.User]++
		}

		// Flag sudo usage by non-root users as potential security concern
		if log.EventType == models.AuthEventSudo && log.SudoUser == "root" && log.User != "root" {
			issues = append(issues, map[string]interface{}{
				"severity":  "WARNING",
				"source":    "auth",
				"title":     "Non-root user executed sudo as root",
				"message":   fmt.Sprintf("User %s executed sudo command as root: %s", log.User, log.Command),
				"user":      log.User,
				"command":   log.Command,
				"timestamp": log.Timestamp,
			})
		}
	}

	// Flag IPs with multiple failed attempts
	for ip, count := range failedAttempts {
		if count > 5 { // Threshold for multiple failed attempts
			issues = append(issues, map[string]interface{}{
				"severity":  "WARNING",
				"source":    "auth",
				"title":     "Multiple failed SSH attempts from IP",
				"message":   fmt.Sprintf("IP %s had %d failed SSH attempts", ip, count),
				"source_ip": ip,
				"attempts":  count,
			})
		}
	}

	// Flag users with multiple failed authentication attempts
	for user, count := range failedUsers {
		if count > 3 { // Threshold for user lockout concern
			issues = append(issues, map[string]interface{}{
				"severity": "WARNING",
				"source":   "auth",
				"title":    "Multiple failed authentication attempts for user",
				"message":  fmt.Sprintf("User %s had %d failed authentication attempts", user, count),
				"user":     user,
				"attempts": count,
			})
		}
	}

	return issues
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
	} else {
		http.Error(w, "Unknown graph type", http.StatusBadRequest)
		return
	}

	// Check if file exists
	if _, err := os.Stat(graphPath); os.IsNotExist(err) {
		http.Error(w, "Graph not found", http.StatusNotFound)
		return
	}

	// Set content type for PNG
	w.Header().Set("Content-Type", "image/png")

	// Serve the PNG file
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

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
