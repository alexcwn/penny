package server

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"penny/internal/models"
)

//go:embed static/*
var staticFiles embed.FS

// Start starts the HTTP server
func Start(port int, data *models.ArchiveData) error {
	// Set the archive data for handlers
	SetArchiveData(data)

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
	http.HandleFunc("/api/issues", handleIssues)
	http.HandleFunc("/api/n2os-config", handleN2OSConfig)
	http.HandleFunc("/api/n2op-logs", handleN2OpLogs)
	http.HandleFunc("/api/n2osjobs-logs", handleN2OSJobLogs)
	http.HandleFunc("/api/health-events", handleHealthEvents)
	http.HandleFunc("/api/database", handleDatabase)
	http.HandleFunc("/api/output-analysis-check", handleOutputAnalysisCheck)
	http.HandleFunc("/api/output-analysis", handleOutputAnalysis)
	http.HandleFunc("/api/goaccess-check", handleGoAccessCheck)
	http.HandleFunc("/api/goaccess", handleGoAccess)
	http.HandleFunc("/api/interface-graphs-check", handleInterfaceGraphsCheck)

	// Serve static files (dashboard UI)
	http.Handle("/", http.FileServer(http.FS(staticFS)))

	// Start server
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Server listening on http://localhost%s\n", addr)

	return http.ListenAndServe(addr, nil)
}
