package models

import "time"

// N2OpEventType represents the type of n2op event
type N2OpEventType string

const (
	N2OpEventHeartbeat       N2OpEventType = "heartbeat"
	N2OpEventUpgradeStart    N2OpEventType = "upgrade_start"
	N2OpEventUpgradeComplete N2OpEventType = "upgrade_complete"
	N2OpEventServiceStart    N2OpEventType = "service_start"
	N2OpEventServiceStop     N2OpEventType = "service_stop"
	N2OpEventSystemStart     N2OpEventType = "system_start"
	N2OpEventSystemStop      N2OpEventType = "system_stop"
	N2OpEventOther           N2OpEventType = "other"
)

// N2OpLogEntry represents a parsed n2op.log entry
type N2OpLogEntry struct {
	Timestamp   time.Time
	EventType   N2OpEventType
	Service     string // For service start/stop events
	Version     string // For version info and heartbeat
	FromVersion string // For upgrade events only
	ToVersion   string // For upgrade events only
	PID         string // For heartbeat logs
	ThreadID    string // For heartbeat logs
	Message     string // Full message
	RawLine     string // Original log line
}

// UpgradeViolation represents an invalid upgrade path
type UpgradeViolation struct {
	Timestamp   time.Time `json:"timestamp"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Description string    `json:"description"`
	DocsURL     string    `json:"docs_url,omitempty"`
}

// HealthEventCategory represents broad categories of health events
type HealthEventCategory string

const (
	HealthCategoryNetwork     HealthEventCategory = "network"
	HealthCategoryAppliance   HealthEventCategory = "appliance"
	HealthCategorySystem      HealthEventCategory = "system"
	HealthCategoryReplication HealthEventCategory = "replication"
	HealthCategoryUpgrade     HealthEventCategory = "upgrade"
	HealthCategoryOther       HealthEventCategory = "other"
)

// HealthEventType represents specific types of health events
type HealthEventType string

const (
	// Network events
	HealthEventLinkUp   HealthEventType = "link_up"
	HealthEventLinkDown HealthEventType = "link_down"

	// Appliance health events
	HealthEventApplianceStale      HealthEventType = "appliance_stale"
	HealthEventApplianceRecovered  HealthEventType = "appliance_recovered"
	HealthEventLastSeenPacket      HealthEventType = "last_seen_packet"
	HealthEventApplianceOffline    HealthEventType = "appliance_offline"
	HealthEventApplianceOnline     HealthEventType = "appliance_online"
	HealthEventApplianceUnreachable HealthEventType = "appliance_unreachable"

	// System events
	HealthEventRecommendedChanges HealthEventType = "recommended_changes"
	HealthEventConfigChange       HealthEventType = "config_change"
	HealthEventResourceAlert      HealthEventType = "resource_alert"

	// Replication events
	HealthEventReplicationIssue   HealthEventType = "replication_issue"
	HealthEventSyncComplete       HealthEventType = "sync_complete"
	HealthEventSyncFailed         HealthEventType = "sync_failed"

	// Upgrade events
	HealthEventUpgradeAvailable   HealthEventType = "upgrade_available"
	HealthEventUpgradeRequired    HealthEventType = "upgrade_required"

	// Generic
	HealthEventOther              HealthEventType = "other"
)

// HealthEventSeverity represents the severity level of a health event
type HealthEventSeverity string

const (
	HealthSeverityInfo     HealthEventSeverity = "info"
	HealthSeverityWarning  HealthEventSeverity = "warning"
	HealthSeverityError    HealthEventSeverity = "error"
	HealthSeverityCritical HealthEventSeverity = "critical"
)

// HealthEvent represents a generic health event from health_logs.csv
type HealthEvent struct {
	ID              string              // UUID from CSV
	Timestamp       time.Time           // Parsed from 'time' field
	RecordCreatedAt time.Time           // Parsed from 'record_created_at'
	ApplianceID     string              // UUID of the appliance (may be empty)
	ApplianceIP     string              // IP address of the appliance
	ApplianceHost   string              // Hostname of the appliance
	Synchronized    bool                // Sync status
	Replicated      bool                // Replication status

	// Parsed from 'info' JSON field
	Description     string              // Human-readable description
	IsStale         *bool               // Pointer to allow nil (for non-stale events)
	LastSeenPacket  string              // For last_seen_packet events
	Port            string              // For link up/down events
	VersionInfo     string              // For upgrade/version events

	// Classification (derived)
	Category        HealthEventCategory // Broad category
	EventType       HealthEventType     // Specific event type
	Severity        HealthEventSeverity // Severity level

	// Raw data
	InfoJSON        string              // Original JSON from 'info' column
}

// DatabaseTable represents a combined view of table size and statistics
type DatabaseTable struct {
	TableName           string
	Size                string  // Human-readable (e.g., "159 MB")
	SizeBytes           int64   // For sorting and calculations
	LastVacuum          string
	LastAutovacuum      string
	LiveTuples          int
	DeadTuples          int
	AutovacuumThreshold int
	NeedsVacuum         bool // If dead_tup exceeds threshold
	IsOversized         bool // If size >= 1 GB
}

// DatabaseDiagnostics contains database health information
type DatabaseDiagnostics struct {
	Tables      []DatabaseTable
	TotalSize   string // Sum of all table sizes
	IssuesCount int    // Tables needing attention (vacuum or oversized)
}

// N2OSJobLogEntry represents a parsed n2osjobs.log entry
type N2OSJobLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	TaskName   string    `json:"task_name"`    // e.g., "IDSApi::CMC::SyncTask"
	DurationMS float64   `json:"duration_ms"`  // Task execution duration in milliseconds
	Source     string    `json:"source"`       // Log file source: "jobs", "jobs.0", "jobs.1", etc.
	LineNumber int       `json:"line_number"`  // Line number within the source file
	RawLine    string    `json:"raw_line"`     // Original log line
}

// N2OSProductionLogEntry represents a parsed production.log entry
type N2OSProductionLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"` // e.g., "4923" from #4923
	Level      string    `json:"level"`      // WARN, INFO, ERROR, DEBUG
	Message    string    `json:"message"`    // Message after "-- :"
	Source     string    `json:"source"`     // Log file source: "production", "production.0", etc.
	LineNumber int       `json:"line_number"`// Line number within the source file
	RawLine    string    `json:"raw_line"`   // Original log line
}

// N2OSMigrateLogEntry represents a single line from n2osmigrate.log
type N2OSMigrateLogEntry struct {
	LineNumber  int    `json:"line_number"`  // Line position in file
	MessageType string `json:"message_type"` // "info", "error", "warning", "metric"
	Content     string `json:"content"`      // The log line content
	IsMultiline bool   `json:"is_multiline"` // True if part of error stacktrace
}

// N2OSMigrateSummary provides overview of migration log
type N2OSMigrateSummary struct {
	TotalEntries     int    `json:"total_entries"`
	HasErrors        bool   `json:"has_errors"`
	ErrorCount       int    `json:"error_count"`
	WarningCount     int    `json:"warning_count"`
	MigrationItems   string `json:"migration_items"`     // Extracted from "DB Migration items: X"
	CurrentDBVersion string `json:"current_db_version"`  // Extracted from "DB Current version: X"
	CompletedSuccess bool   `json:"completed_success"`   // True if ends with "All migrations performed!"
}

// N2OSIDSLogEntry represents a parsed n2os_ids.log entry
type N2OSIDSLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`  // e.g., "91033"
	ThreadID   string    `json:"thread_id"`   // e.g., "599027"
	Level      string    `json:"level"`       // DEBUG, INFO, WARN, ERROR
	Message    string    `json:"message"`     // Full message text
	Source     string    `json:"source"`      // "ids", "ids.0", "ids.1", etc.
	LineNumber int       `json:"line_number"` // Line number in source file
	RawLine    string    `json:"raw_line"`    // Original log line
}

// N2OSIDSEventsLogEntry represents a parsed n2os_ids_events.log entry
type N2OSIDSEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`  // e.g., "91033"
	ThreadID   string    `json:"thread_id"`   // e.g., "598998"
	Protocol   string    `json:"protocol"`    // e.g., "dce-rpc", extracted from EVENT:[protocol]
	Event      string    `json:"event"`       // Full event message
	Source     string    `json:"source"`      // "events", "events.0", "events.1", etc.
	LineNumber int       `json:"line_number"` // Line number in source file
	RawLine    string    `json:"raw_line"`    // Original log line
}

// N2OSPumaLogEntry represents a parsed puma.log entry
type N2OSPumaLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	PID        string    `json:"pid"`
	Level      string    `json:"level"`    // "INFO", "WARN", or ""
	Message    string    `json:"message"`
	Source     string    `json:"source"`   // "puma", "puma.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSPumaErrLogEntry represents a parsed puma-err.log entry
type N2OSPumaErrLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`   // "puma-err", "puma-err.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSSpLogEntry represents a parsed n2ossp.log entry (Ruby logger format)
type N2OSSpLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	PID        string    `json:"pid"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "sp", "sp.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSStrategistLogEntry represents a parsed n2os_strategist.log entry
type N2OSStrategistLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Component  string    `json:"component"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "strategist", "strategist.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSStixDBLogEntry represents a parsed n2os_stixdb.log entry
type N2OSStixDBLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "stixdb", "stixdb.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSVALogEntry represents a parsed n2os_va.log entry
type N2OSVALogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "va", "va.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSVAEventsLogEntry represents a parsed n2os_va_events.log entry
type N2OSVAEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Event      string    `json:"event"`       // payload after "EVENT:"
	Source     string    `json:"source"`      // "va_events", "va_events.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSTraceLogEntry represents a parsed n2os_trace.log entry
type N2OSTraceLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "trace", "trace.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSTraceEventsLogEntry represents a parsed n2os_trace_events.log entry
type N2OSTraceEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Event      string    `json:"event"`       // payload after "EVENT:"
	Source     string    `json:"source"`      // "trace_events", "trace_events.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSSandboxLogEntry represents a parsed n2os_sandbox.log entry
type N2OSSandboxLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "sandbox", "sandbox.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSSandboxEventsLogEntry represents a parsed n2os_sandbox_events.log entry
type N2OSSandboxEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Event      string    `json:"event"`       // payload after "EVENT:"
	Source     string    `json:"source"`      // "sandbox_events", "sandbox_events.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSReverseLogEntry represents a parsed n2os_reverse.log entry
type N2OSReverseLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`      // "reverse", "reverse.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSReverseEventsLogEntry represents a parsed n2os_reverse_events.log entry
type N2OSReverseEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Event      string    `json:"event"`       // payload after "EVENT:"
	Source     string    `json:"source"`      // "reverse_events", "reverse_events.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSJobDelayedLogEntry represents a parsed n2osdelayedjobs.log entry
type N2OSJobDelayedLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	TaskName   string    `json:"task_name"`   // e.g., "IDSApi::CMC::SyncTask"
	DurationMS float64   `json:"duration_ms"` // Task execution duration in milliseconds
	Source     string    `json:"source"`      // "delayed_jobs"
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSJobDILogEntry represents a parsed n2osjobs_di.log entry
type N2OSJobDILogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	TaskName   string    `json:"task_name"`   // e.g., "IDSApi::DataIntegrationTask"
	DurationMS float64   `json:"duration_ms"` // Task execution duration in milliseconds
	Source     string    `json:"source"`      // "jobs_di", "jobs_di.0", etc.
	LineNumber int       `json:"line_number"` // Line number within the source file
	RawLine    string    `json:"raw_line"`    // Original log line
}

// N2OSOtelcolLogEntry represents a parsed n2os_otelcol.log entry
type N2OSOtelcolLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`   // info, error, warn, debug
	Caller     string    `json:"caller"`  // e.g. "internal/queue_sender.go:50"
	Message    string    `json:"message"` // human-readable message
	Fields     string    `json:"fields"`  // raw JSON fields blob (everything after message)
	Source     string    `json:"source"`  // "otelcol", "otelcol.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSRCLogEntry represents a parsed n2os_rc.log entry
type N2OSRCLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`    // "rc", "rc.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSRCEventsLogEntry represents a parsed n2os_rc_events.log entry
type N2OSRCEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`
	ThreadID   string    `json:"thread_id"`
	Event      string    `json:"event"`      // full payload after "EVENT:"
	Source     string    `json:"source"`     // "rc_events", "rc_events.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSCPE2CVELogEntry represents a parsed n2os_cpe2cve.log entry
type N2OSCPE2CVELogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Message    string    `json:"message"`   // Full message text
	Source     string    `json:"source"`    // "cpe2cve", "cpe2cve.0", etc.
	LineNumber int       `json:"line_number"`
	RawLine    string    `json:"raw_line"`
}

// N2OSAlertLogEntry represents a parsed n2os_alert.log entry
type N2OSAlertLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`  // e.g., "76392"
	ThreadID   string    `json:"thread_id"`   // e.g., "100487"
	Level      string    `json:"level"`       // INFO, DEBUG, WARN, ERROR, SIGNAL
	Message    string    `json:"message"`     // Full message text
	Source     string    `json:"source"`      // "alert" (no rotation)
	LineNumber int       `json:"line_number"` // Line number in source file
	RawLine    string    `json:"raw_line"`    // Original log line
}

// N2OSAlertEventsLogEntry represents a parsed n2os_alert_events.log entry
type N2OSAlertEventsLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	ProcessID  string    `json:"process_id"`  // e.g., "20542"
	ThreadID   string    `json:"thread_id"`   // e.g., "100512"
	EventType  string    `json:"event_type"`  // Extracted from JSON (e.g., "stop", "metrics")
	Event      string    `json:"event"`       // Full event JSON string
	Source     string    `json:"source"`      // "alert_events"
	LineNumber int       `json:"line_number"` // Line number in source file
	RawLine    string    `json:"raw_line"`    // Original log line
}

// DatabaseSampleData represents parsed sample data
type DatabaseSampleData struct {
	Tables      []GenericTable `json:"tables"`
	TotalTables int            `json:"total_tables"`
	ParsedAt    time.Time      `json:"parsed_at"`
}

// GenericTable represents a dynamically parsed table
type GenericTable struct {
	Name     string              `json:"name"`
	Columns  []string            `json:"columns"`
	Rows     []map[string]string `json:"rows"`
	RowCount int                 `json:"row_count"`
	IsEmpty  bool                `json:"is_empty"`
}

// N2OSConfEntry represents a parsed line from n2os.conf.gz
type N2OSConfEntry struct {
	LineNumber  int    `json:"line_number"`
	CommandType string `json:"command_type"` // "network_map" or "link"
	Address     string `json:"address"`      // IP or MAC
	UUID        string `json:"uuid"`         // For network_map
	Params      string `json:"params"`       // For link (remaining params)
}

// AddressCount represents a count of occurrences for an address
type AddressCount struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

// N2OSConfStats contains statistics about the n2os.conf.gz file
type N2OSConfStats struct {
	TotalLines      int               `json:"total_lines"`
	Timestamp       int64             `json:"timestamp"`
	CommandCounts   map[string]int    `json:"command_counts"`
	TopAddresses    []AddressCount    `json:"top_addresses"`
	UniqueAddresses int               `json:"unique_addresses"`
	UniqueUUIDs     int               `json:"unique_uuids"`
}

// N2OSConfData holds parsed data from n2os.conf.gz
type N2OSConfData struct {
	RawContent string          `json:"raw_content"`
	Entries    []N2OSConfEntry `json:"entries"`
	Stats      N2OSConfStats   `json:"stats"`
}

// ArchiveData holds all parsed data from a support archive
// Appliance represents a Guardian appliance from appliance.csv
type Appliance struct {
	IP                  string    `json:"ip"`
	LastSync            time.Time `json:"last_sync"`
	ID                  string    `json:"id"`
	Info                string    `json:"info"`
	Allowed             bool      `json:"allowed"`
	SyncThroughput      int64     `json:"sync_throughput"`
	IsUpdating          bool      `json:"is_updating"`
	MapPosition         string    `json:"map_position"`
	Site                string    `json:"site"`
	Host                string    `json:"host"`
	Time                time.Time `json:"time"`
	Synchronized        bool      `json:"synchronized"`
	Replicated          bool      `json:"replicated"`
	DeletedAt           int64     `json:"deleted_at"`
	Health              string    `json:"health"`
	ApplianceID         string    `json:"appliance_id"`
	ApplianceIP         string    `json:"appliance_ip"`
	ApplianceHost       string    `json:"appliance_host"`
	ForceUpdate         bool      `json:"force_update"`
	Model               string    `json:"model"`
	LastSeenPacket      string    `json:"last_seen_packet"`
}

type ArchiveData struct {
	Metadata           ArchiveMetadata
	SystemInfo         SystemInfo
	Logs               Logs
	Processes          []Process
	NetworkConfig      NetworkConfig
	Storage            Storage
	N2OSConfig         N2OSConfig
	N2OSConfData       N2OSConfData
	N2OpLogs           []N2OpLogEntry
	UpgradeViolations  []UpgradeViolation
	HealthEvents       []HealthEvent
	Database           DatabaseDiagnostics
	DatabaseSampleData DatabaseSampleData
	BPFSnapshots       []BPFSnapshot
	BPFComparisons     []BPFComparison
	N2OSJobLogs        []N2OSJobLogEntry
	N2OSJobDILogs      []N2OSJobDILogEntry
	N2OSJobDelayedLogs []N2OSJobDelayedLogEntry
	N2OSProductionLogs []N2OSProductionLogEntry
	N2OSMigrateLogs    []N2OSMigrateLogEntry
	N2OSMigrateSummary N2OSMigrateSummary
	N2OSIDSLogs        []N2OSIDSLogEntry
	N2OSIDSEventsLogs  []N2OSIDSEventsLogEntry
	N2OSAlertLogs       []N2OSAlertLogEntry
	N2OSAlertEventsLogs []N2OSAlertEventsLogEntry
	N2OSCPE2CVELogs     []N2OSCPE2CVELogEntry
	N2OSRCLogs           []N2OSRCLogEntry
	N2OSRCEventsLogs     []N2OSRCEventsLogEntry
	N2OSReverseLogs       []N2OSReverseLogEntry
	N2OSReverseEventsLogs []N2OSReverseEventsLogEntry
	N2OSTraceLogs         []N2OSTraceLogEntry
	N2OSTraceEventsLogs   []N2OSTraceEventsLogEntry
	N2OSSandboxLogs       []N2OSSandboxLogEntry
	N2OSSandboxEventsLogs []N2OSSandboxEventsLogEntry
	N2OSVALogs            []N2OSVALogEntry
	N2OSVAEventsLogs      []N2OSVAEventsLogEntry
	N2OSStixDBLogs        []N2OSStixDBLogEntry
	N2OSStrategistLogs    []N2OSStrategistLogEntry
	N2OSSpLogs            []N2OSSpLogEntry
	N2OSPumaLogs          []N2OSPumaLogEntry
	N2OSPumaErrLogs       []N2OSPumaErrLogEntry
	N2OSOtelcolLogs      []N2OSOtelcolLogEntry
	Appliances          []Appliance
	HCUpgradePath       string // Output from hc_upgrade_path.sh, empty if script not found or not run
	HCDisks             string // Output from hc_disks.sh, empty if script not found or not run
	ByosResults         []ByosResult
	LandingView         string // resolved landing view, defaults to "system"
	Theme               string // "dark" or "light", defaults to "light"
	KnownIssueResults   []KnownIssueResult
}

// ByosResult holds the output of a single BYOS script execution
type ByosResult struct {
	Name   string `json:"name"`
	Tag    string `json:"tag,omitempty"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// KnownIssueResult is a matched known issue with details extracted by its script.
type KnownIssueResult struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Workaround  string `json:"workaround,omitempty"`
	URL         string `json:"url,omitempty"`
}

// ArchiveMetadata contains basic info about the archive
type ArchiveMetadata struct {
	ArchivePath   string
	ExtractedPath string
	ParsedAt      time.Time
	Version       string
	Hostname      string
	Platform      string
	Timezone      string // IANA timezone from n2os.conf.user (e.g., "Australia/Perth"), defaults to "UTC"
}

// License represents a software license from licenses.json
type License struct {
	Licensee            string
	Type                string
	Status              string
	BundleName          string
	Purpose             string
	ExpireDate          time.Time
	ActualLicensedNodes string
	SupportedNodes      string
	IsDisabled          bool
}

// CMCConfig contains Central Management Console configuration
type CMCConfig struct {
	// Sync configuration
	SyncTo   string `json:"sync_to"`   // URL of CMC or Vantage
	SyncMode string `json:"sync_mode"` // e.g., "Send Only Visible Alerts"

	// Sync data types
	SyncConfVariables     bool `json:"sync_conf_variables"`
	SyncConfPhysicalLinks bool `json:"sync_conf_physical_links"`
	SyncConfNodes         bool `json:"sync_conf_nodes"`
	SyncConfLinks         bool `json:"sync_conf_links"`

	// Advanced settings
	MultiContext             bool `json:"multi_context"`
	SendBundleWithoutUpdating bool `json:"send_bundle_without_updating"`

	// Proxy configuration
	ProxyEnabled     bool   `json:"proxy_enabled"`
	ProxyHost        string `json:"proxy_host,omitempty"`
	ProxyPort        string `json:"proxy_port,omitempty"`
	ProxyAuthEnabled bool   `json:"proxy_auth_enabled"`

	// Configuration availability
	HasConfig bool `json:"has_config"` // True if any CMC settings found
}

// SystemInfo contains system-level information
type SystemInfo struct {
	Product           string
	Version           string
	Platform          string
	Uptime            string
	Hostname          string
	MachineID         string
	ApplianceUUID     string
	FreeBSDRelease    string
	KernelVersion     string
	Timezone          string // e.g., "America/New_York", "UTC" (default if not configured)
	CreationTimestamp time.Time
	// Asset metrics from meta.json
	TotalNodes        int // Total discovered network assets
	TotalLinks        int // Total network connections between assets
	TotalVariables    int // Custom variables count
	NodeElementLimit  int // Network elements limit from n2os_ids.log
	// Hardware info from sysctl.txt
	CPUModel        string
	CPUCores        int
	PhysicalMemory  string // Human-readable (e.g., "16 GB")
	AvailableMemory string // Human-readable
	BootTime        time.Time
	// Licenses
	Licenses []License
	// CMC Configuration
	CMCConfig CMCConfig `json:"cmc_config"`
}

// AuthEventType represents the type of authentication event
type AuthEventType string

const (
	AuthEventSudo        AuthEventType = "sudo"
	AuthEventSSHSuccess  AuthEventType = "ssh_success"
	AuthEventSSHFailed   AuthEventType = "ssh_failed"
	AuthEventLogin       AuthEventType = "login"
	AuthEventAuthFailure AuthEventType = "auth_failure"
	AuthEventSecurity    AuthEventType = "security"
	AuthEventOther       AuthEventType = "other"
)

// AuthLogEntry represents a parsed auth.log or security entry
type AuthLogEntry struct {
	Timestamp time.Time
	Hostname  string
	Process   string
	PID       string
	User      string
	EventType AuthEventType
	SudoUser  string // Target user for sudo commands
	Command   string // Command executed via sudo
	SourceIP  string // Source IP for SSH events
	SessionID string // Session ID for login events
	Message   string // Raw message
	Level     string // INFO, WARNING, ERROR
	RawLine   string // Original log line
	Source    string // "auth", "auth.0", "security", etc.
}

// Logs contains all parsed log data
type Logs struct {
	Messages        []LogEntry
	NginxErrors     []NginxLogEntry
	NginxAccess     []LogEntry
	WebserverDaemon []LogEntry
	AuthLog         []AuthLogEntry
}

// LogEntry represents a parsed syslog entry
type LogEntry struct {
	Timestamp  time.Time
	Hostname   string
	Process    string
	PID        string
	Message    string
	Level      string
	RawLine    string
	Source     string // Source file (e.g., "nginx-access.log")
	LineNumber int    // Line number in source file
}

// NginxLogEntry represents a parsed nginx error log entry
type NginxLogEntry struct {
	Timestamp    time.Time
	Level        string
	PID          string
	TID          string
	ConnectionID string
	Message      string
	Client       string
	Server       string
	Request      string
	Upstream     string
	Host         string
	Referrer     string
	RawLine      string
	Source       string // Source file (e.g., "nginx-error.log")
	LineNumber   int    // Line number in source file
}

// Process represents a running process from ps output
type Process struct {
	User    string
	PID     string
	CPU     string
	Memory  string
	VSZ     string
	RSS     string
	TT      string
	Stat    string
	Started string
	Time    string
	Command string
}

// NetstatDropEntry represents one row from netstat_drops.txt
type NetstatDropEntry struct {
	Name    *string `json:"Name"`
	Mtu     *string `json:"Mtu"`
	Network *string `json:"Network"`
	Address *string `json:"Address"`
	Ipkts   *string `json:"Ipkts"`
	Ierrs   *string `json:"Ierrs"`
	Idrop   *string `json:"Idrop"`
	Ibytes  *string `json:"Ibytes"`
	Opkts   *string `json:"Opkts"`
	Oerrs   *string `json:"Oerrs"`
	Obytes  *string `json:"Obytes"`
	Coll    *string `json:"Coll"`
	Drop    *string `json:"Drop"`
}

// NetstatRouteEntry represents one row from netstat_routing.txt
type NetstatRouteEntry struct {
	Destination *string `json:"Destination"`
	Gateway     *string `json:"Gateway"`
	Flags       *string `json:"Flags"`
	Netif       *string `json:"Netif"`
	Expire      *string `json:"Expire"`
}

// NetworkConfig contains network configuration
type NetworkConfig struct {
	RcConf          map[string]string
	Hostname        string
	Interfaces      []NetworkInterface
	DefaultGW       string
	DNS             string // DNS servers separated by " / "
	RawIfconfigData string
	NetstatDrops    []NetstatDropEntry
	NetstatRoutes   []NetstatRouteEntry
}

// NetworkInterface represents a network interface config
type NetworkInterface struct {
	Name             string
	PhysicalName     string // e.g., igb0, em0 (from rc.conf mapping)
	IPAddress        string
	Netmask          string
	NetmaskHex       string
	NetmaskDecimal   string
	Broadcast        string
	MACAddress       string
	Status           string // active, no carrier, etc.
	Media            string
	MTU              string
	Metric           string
	Flags            []string
	FlagsCount       int
	FlagsHex         string
	Options          string
	OptionsHex       string
	Config           string // Original rc.conf config line
	RawIfconfigBlock string // Raw ifconfig output for this interface
}

// BPFStat represents a single BPF (Berkeley Packet Filter) statistics entry
type BPFStat struct {
	PID        int
	Interface  string
	Flags      string
	Recv       int64 // Packets received
	Drop       int64 // Packets dropped
	Match      int64 // Packets matched
	Sblen      int64 // Send buffer length
	Hblen      int64 // Hold buffer length
	Command    string
	Timestamp  time.Time // When this snapshot was taken
	SnapshotID string    // Identifier for the snapshot (e.g., filename)
}

// BPFSnapshot represents a collection of BPF stats at a point in time
type BPFSnapshot struct {
	Timestamp time.Time
	Filename  string
	Stats     []BPFStat
}

// BPFComparison represents the delta between two BPF snapshots
type BPFComparison struct {
	Interface      string
	PID            int
	Command        string
	RecvDelta      int64
	DropDelta      int64
	MatchDelta     int64
	SblenDelta     int64
	HblenDelta     int64
	RecvRate       float64 // Packets per second
	DropRate       float64 // Packets per second
	TimeDelta      float64 // Seconds between snapshots
	DropPercentage float64 // Percentage of packets dropped
	BufferGrowth   float64 // Percentage growth in send buffer
	HasIssue       bool    // True if drops > 0 or buffer growth > 200%
}

// DiskUsageEntry represents a single disk usage entry from diskusage.txt
type DiskUsageEntry struct {
	Size      string // Human-readable size (e.g., "15G", "4.7G")
	SizeBytes int64  // Size in bytes for sorting
	Path      string // Directory path
}

// Storage contains storage-related information
type Storage struct {
	ZpoolStatus    []ZpoolStatus
	DiskInfo       []DiskInfo
	DiskUsage      []DiskUsageEntry // Parsed disk usage entries
	DiskUsageRaw   string           // Raw diskusage.txt content
	DiskFree       string
	Fstab          []FstabEntry
	ZfsList        []ZfsDataset
}

// ZpoolStatus represents zpool status output
type ZpoolStatus struct {
	Pool      string
	State     string
	Status    string
	Scan      string
	Config    []ZpoolDevice
	Errors    string
	RawOutput string
}

// ZpoolDevice represents a device in zpool
type ZpoolDevice struct {
	Name  string
	State string
	Read  string
	Write string
	Cksum string
}

// DiskWriteCycleLimits maps Device Model strings to their rated write cycle limits.
// Source: Nozomi appliance SSD specifications.
var DiskWriteCycleLimits = map[string]int{
	`2.5" SATA SSD 3IE4`:   20000, // NSG-L
	`2.5" SATA SSD 3IE2-P`: 20000, // NSG-H mk1 / NSG-HS mk1
	"SSO064GTLSW-SDC":      20000, // NS20
	"TS640GSSD550I":        20000, // NS20
	"TS64GSSD420I":         20000, // NS1R / RS1R
}

// DiskInfo represents SMART disk information
type DiskInfo struct {
	Device       string
	Model        string
	Serial       string
	Capacity     string
	Health       string
	Temperature  string
	PowerOnHours string
	RawOutput    string

	// SMART attributes (raw values from smartctl output)
	SMARTAvailable  bool  // Whether SMART is supported (false = likely a VM)
	RemainingLifePct int  // Attr 169 RAW_VALUE — remaining lifetime percentage
	HostWritesLBA   int64 // Attr 241 RAW_VALUE — total LBAs written by host
	HostReadsLBA    int64 // Attr 242 RAW_VALUE — total LBAs read by host
	CapacityGB      int   // Numeric capacity in GB (parsed from User Capacity)

	// Computed health results
	WriteCycles     int  // Calculated: (HostWritesLBA * 32 / 1024) / CapacityGB
	WriteCycleLimit int  // Device-specific rated write cycle limit (0 = unknown)

	// Health assessment
	DiskHealthStatus string // "Healthy", "Critical", "FRIED", "Unknown", "VM"
	LifetimeCritical bool   // true if RemainingLifePct < 20 or > 100
	CyclesExceeded   bool   // true if WriteCycles > WriteCycleLimit
}

// FstabEntry represents an entry in /etc/fstab
type FstabEntry struct {
	Device     string
	MountPoint string
	FSType     string
	Options    string
	Dump       string
	Pass       string
}

// ZfsDataset represents a ZFS dataset from zfs list
type ZfsDataset struct {
	Name        string
	Used        string
	Available   string
	Refer       string
	MountPoint  string
	UsedPercent float64
}

// N2OSConfig contains N2OS configuration
type N2OSConfig struct {
	RawContent string
	Settings   []N2OSSetting
}

// N2OSSetting represents a single N2OS configuration setting
type N2OSSetting struct {
	Key         string
	Value       string
	MaskedValue string
	IsSensitive bool
	Description string
	DocsURL     string
}

// HealthCheck contains pre-computed health check data
type HealthCheck struct {
	Overview string
	Alerts   []string
	PGDiag   PostgresDiagnostics
	Stats    map[string]interface{}
}

// PostgresDiagnostics contains PostgreSQL diagnostic info
type PostgresDiagnostics struct {
	Activity string
	Bloat    string
	Size     string
	Schema   string
	Stats    string
}

// ParseError represents a parsing error
type ParseError struct {
	File    string
	Line    int
	Message string
	Err     error
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return "parse error in " + e.File + " at line " + string(rune(e.Line)) + ": " + e.Message
	}
	return "parse error in " + e.File + ": " + e.Message
}
