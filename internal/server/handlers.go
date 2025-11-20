package server

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
