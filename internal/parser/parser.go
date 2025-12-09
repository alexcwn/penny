package parser

import (
	"fmt"
	"math/rand"
	"penny/internal/models"
)

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
