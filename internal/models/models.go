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

// ArchiveData holds all parsed data from a support archive
type ArchiveData struct {
	Metadata      ArchiveMetadata
	SystemInfo    SystemInfo
	Logs          Logs
	Processes     []Process
	NetworkConfig NetworkConfig
	Storage       Storage
	N2OSConfig    N2OSConfig
	N2OpLogs      []N2OpLogEntry
	HealthEvents  []HealthEvent
	Database      DatabaseDiagnostics
}

// ArchiveMetadata contains basic info about the archive
type ArchiveMetadata struct {
	ArchivePath   string
	ExtractedPath string
	ParsedAt      time.Time
	Version       string
	Hostname      string
	Platform      string
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

// SystemInfo contains system-level information
type SystemInfo struct {
	Product           string
	Version           string
	Platform          string
	Uptime            string
	Hostname          string
	MachineID         string
	FreeBSDRelease    string
	KernelVersion     string
	CreationTimestamp time.Time
	// Asset metrics from meta.json
	TotalNodes     int // Total discovered network assets
	TotalLinks     int // Total network connections between assets
	TotalVariables int // Custom variables count
	// Hardware info from sysctl.txt
	CPUModel       string
	CPUCores       int
	PhysicalMemory string // Human-readable (e.g., "16 GB")
	AvailableMemory string // Human-readable
	BootTime       time.Time
	// Licenses
	Licenses []License
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

// AuthLogEntry represents a parsed auth.log entry
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
}

// Logs contains all parsed log data
type Logs struct {
	Messages        []LogEntry
	NginxErrors     []NginxLogEntry
	WebserverDaemon []LogEntry
	AuthLog         []AuthLogEntry
}

// LogEntry represents a parsed syslog entry
type LogEntry struct {
	Timestamp time.Time
	Hostname  string
	Process   string
	PID       string
	Message   string
	Level     string
	RawLine   string
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

// NetworkConfig contains network configuration
type NetworkConfig struct {
	RcConf          map[string]string
	Hostname        string
	Interfaces      []NetworkInterface
	DefaultGW       string
	DNS             string // DNS servers separated by " / "
	RawIfconfigData string
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

// Storage contains storage-related information
type Storage struct {
	ZpoolStatus []ZpoolStatus
	DiskInfo    []DiskInfo
	DiskUsage   string
	DiskFree    string
	Fstab       []FstabEntry
	ZfsList     []ZfsDataset
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
