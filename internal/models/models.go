package models

import "time"

// ArchiveData holds all parsed data from a support archive
type ArchiveData struct {
	Metadata      ArchiveMetadata
	SystemInfo    SystemInfo
	Logs          Logs
	Processes     []Process
	NetworkConfig NetworkConfig
	Storage       Storage
	N2OSConfig    N2OSConfig
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

// SystemInfo contains system-level information
type SystemInfo struct {
	Product        string
	Version        string
	Platform       string
	Uptime         string
	Hostname       string
	FreeBSDRelease string
	KernelVersion  string
}

// Logs contains all parsed log data
type Logs struct {
	Messages        []LogEntry
	NginxErrors     []NginxLogEntry
	WebserverDaemon []LogEntry
	AuthLog         []LogEntry
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
	RcConf     map[string]string
	Hostname   string
	Interfaces []NetworkInterface
	DefaultGW  string
}

// NetworkInterface represents a network interface config
type NetworkInterface struct {
	Name      string
	IPAddress string
	Netmask   string
	Config    string
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
