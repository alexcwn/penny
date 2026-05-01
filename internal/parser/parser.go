package parser

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"penny/internal/models"
	"strings"
	"time"
)

// resolveN2OSLogDir returns the n2os log directory, trying log/n2os (backup archives)
// before falling back to data/log/n2os (support archives).
func resolveN2OSLogDir(baseDir string) string {
	candidate := filepath.Join(baseDir, "log", "n2os")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return filepath.Join(baseDir, "data", "log", "n2os")
}

// resolveLogDir returns the top-level log directory, trying log/ (backup archives)
// before falling back to data/log/ (support archives).
func resolveLogDir(baseDir string) string {
	candidate := filepath.Join(baseDir, "log")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return filepath.Join(baseDir, "data", "log")
}

// resolveCfgDir returns the cfg directory, trying cfg/ (backup archives)
// before falling back to data/cfg/ (support archives).
func resolveCfgDir(baseDir string) string {
	candidate := filepath.Join(baseDir, "cfg")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return filepath.Join(baseDir, "data", "cfg")
}

// Playful verbs for progress indicators used throughout the application
var playfulVerbs = []string{
	"Accomplishing", "Actioning", "Actualizing", "Baking", "Brewing",
	"Calculating", "Cerebrating", "Churning", "Clauding", "Coalescing",
	"Cogitating", "Computing", "Conjuring", "Considering", "Cooking",
	"Crafting", "Creating", "Crunching", "Deliberating", "Determining",
	"Doing", "Effecting", "Finagling", "Forging", "Forming",
	"Generating", "Hatching", "Herding", "Honking", "Hustling",
	"Ideating", "Inferring", "Manifesting", "Marinating", "Moseying",
	"Mulling", "Mustering", "Musing", "Noodling", "Percolating",
	"Pondering", "Processing", "Puttering", "Reticulating", "Ruminating",
	"Schlepping", "Shucking", "Simmering", "Smooshing", "Spinning",
	"Stewing", "Synthesizing", "Thinking", "Transmuting", "Vibing",
	"Working", "Chatgpt'ing", "Groking", "Copiloting", "Deepseeking",
	"Nick'ing", "Andrew'ing", "Hiro'ing", "Scott'ing", "Omar'ing", "Saverio'ing",
}

// GetRandomVerb returns a random playful verb for progress indicators
func GetRandomVerb() string {
	return playfulVerbs[rand.Intn(len(playfulVerbs))]
}

// ParseLogs parses all log files
func ParseLogs(dir string, data *models.ArchiveData) error {
	// Parse syslog messages
	fmt.Printf("    %s syslog messages...", GetRandomVerb())
	messages, err := ParseMessagesLog(dir)
	if err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
		data.Logs.Messages = messages
	}

	// Parse nginx error logs
	fmt.Printf("    %s nginx error logs...", GetRandomVerb())
	nginxErrors, err := ParseNginxErrorLogs(dir)
	if err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
		data.Logs.NginxErrors = nginxErrors
	}

	// Parse nginx access logs
	fmt.Printf("    %s nginx access logs...", GetRandomVerb())
	nginxAccess, err := ParseNginxAccessLogs(dir)
	if err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
		data.Logs.NginxAccess = nginxAccess
	}

	// Parse auth logs
	fmt.Printf("    %s authentication logs...", GetRandomVerb())
	authLogs, err := ParseAuthLog(dir)
	if err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
		data.Logs.AuthLog = authLogs
	}

	// Parse N2OS operation logs
	fmt.Printf("    %s N2OS operation logs...", GetRandomVerb())
	if err := ParseN2OpLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse health check logs
	fmt.Printf("    %s health check logs...", GetRandomVerb())
	if err := ParseHealthLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse database diagnostics
	fmt.Printf("    %s database diagnostics...", GetRandomVerb())
	if err := ParseDatabaseDiagnostics(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS system configuration (must be before production logs to extract timezone)
	fmt.Printf("    %s N2OS configuration...", GetRandomVerb())
	if err := ParseN2OSConf(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS job logs
	fmt.Printf("    %s N2OS job logs...", GetRandomVerb())
	if err := ParseN2OSJobLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS job DI logs
	fmt.Printf("    %s N2OS job DI logs...", GetRandomVerb())
	if err := ParseN2OSJobDILogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS delayed job logs
	fmt.Printf("    %s N2OS delayed job logs...", GetRandomVerb())
	if err := ParseN2OSDelayedJobLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS production logs
	fmt.Printf("    %s N2OS production logs...", GetRandomVerb())
	if err := ParseN2OSProductionLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS migration logs
	fmt.Printf("    %s N2OS migration logs...", GetRandomVerb())
	if err := ParseN2OSMigrateLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS IDS logs
	fmt.Printf("    %s N2OS IDS logs...", GetRandomVerb())
	if err := ParseN2OSIDSLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS IDS events logs
	fmt.Printf("    %s N2OS IDS events logs...", GetRandomVerb())
	if err := ParseN2OSIDSEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Alert logs (both alert.log and alert_events.log)
	fmt.Printf("    %s N2OS alert logs...", GetRandomVerb())
	if err := ParseN2OSAlertLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS CPE2CVE logs
	fmt.Printf("    %s N2OS CPE2CVE logs...", GetRandomVerb())
	if err := ParseN2OSCPE2CVELogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS otelcol logs
	fmt.Printf("    %s N2OS otelcol logs...", GetRandomVerb())
	if err := ParseN2OSOtelcolLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS RC logs
	fmt.Printf("    %s N2OS RC logs...", GetRandomVerb())
	if err := ParseN2OSRCLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS RC events logs
	fmt.Printf("    %s N2OS RC events logs...", GetRandomVerb())
	if err := ParseN2OSRCEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Trace logs
	fmt.Printf("    %s N2OS Trace logs...", GetRandomVerb())
	if err := ParseN2OSTraceLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Trace events logs
	fmt.Printf("    %s N2OS Trace events logs...", GetRandomVerb())
	if err := ParseN2OSTraceEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Sandbox logs
	fmt.Printf("    %s N2OS Sandbox logs...", GetRandomVerb())
	if err := ParseN2OSSandboxLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Sandbox events logs
	fmt.Printf("    %s N2OS Sandbox events logs...", GetRandomVerb())
	if err := ParseN2OSSandboxEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Reverse logs
	fmt.Printf("    %s N2OS Reverse logs...", GetRandomVerb())
	if err := ParseN2OSReverseLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Reverse events logs
	fmt.Printf("    %s N2OS Reverse events logs...", GetRandomVerb())
	if err := ParseN2OSReverseEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS VA logs
	fmt.Printf("    %s N2OS VA logs...", GetRandomVerb())
	if err := ParseN2OSVALogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS VA events logs
	fmt.Printf("    %s N2OS VA events logs...", GetRandomVerb())
	if err := ParseN2OSVAEventsLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS StixDB logs
	fmt.Printf("    %s N2OS StixDB logs...", GetRandomVerb())
	if err := ParseN2OSStixDBLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS Strategist logs
	fmt.Printf("    %s N2OS Strategist logs...", GetRandomVerb())
	if err := ParseN2OSStrategistLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS SP logs
	fmt.Printf("    %s N2OS SP logs...", GetRandomVerb())
	if err := ParseN2OSSpLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse Puma logs
	fmt.Printf("    %s Puma logs...", GetRandomVerb())
	if err := ParseN2OSPumaLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse Puma error logs
	fmt.Printf("    %s Puma error logs...", GetRandomVerb())
	if err := ParseN2OSPumaErrLogs(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse database sample data
	fmt.Printf("    %s database sample data...", GetRandomVerb())
	if err := ParseDatabaseSampleData(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse appliances
	fmt.Printf("    %s appliances...", GetRandomVerb())
	if err := ParseAppliances(dir, data); err != nil {
		fmt.Printf(" ❌\n")
	} else {
		fmt.Printf(" ✅\n")
	}

	return nil
}

// parseN2OSTimestamp parses the common N2OS log timestamp format
// (e.g. "2025-10-01T08:02:08.280 +0200"), trying millisecond precision first.
func parseN2OSTimestamp(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000 -0700", s)
	if err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05 -0700", s)
}

// extractLogSource derives a display source name from a log file path.
// For the current (non-rotated) file it returns label; for rotated files
// (stem.N) it returns label.N.
func extractLogSource(filename, stem, label string) string {
	base := filepath.Base(filename)
	if base == stem {
		return label
	}
	if idx := strings.LastIndex(base, "."); idx != -1 {
		return label + "." + base[idx+1:]
	}
	return label
}

// collectRotatedLogs reads rotated log files (baseName.rotations down to baseName.0)
// then the current file (baseName), collecting all successfully parsed entries.
func collectRotatedLogs[E any](
	logDir, baseName string,
	rotations int,
	parse func(path string) ([]E, error),
) []E {
	var all []E
	for i := rotations; i >= 0; i-- {
		path := filepath.Join(logDir, fmt.Sprintf("%s.%d", baseName, i))
		if entries, err := parse(path); err == nil {
			all = append(all, entries...)
		}
	}
	path := filepath.Join(logDir, baseName)
	if entries, err := parse(path); err == nil {
		all = append(all, entries...)
	}
	return all
}
