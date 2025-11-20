package parser

import (
	"penny/internal/models"
)

// ParseLogs parses all log files
func ParseLogs(dir string, data *models.ArchiveData) error {
	// Parse syslog messages
	messages, err := ParseMessagesLog(dir)
	if err != nil {
		return err
	}
	data.Logs.Messages = messages

	// Parse nginx error logs
	nginxErrors, err := ParseNginxErrorLogs(dir)
	if err != nil {
		return err
	}
	data.Logs.NginxErrors = nginxErrors

	// Parse auth logs
	authLogs, err := ParseAuthLog(dir)
	if err != nil {
		return err
	}
	data.Logs.AuthLog = authLogs

	// Parse N2OS operation logs
	if err := ParseN2OpLogs(dir, data); err != nil {
		// Non-fatal error, just skip if files don't exist
		// Could log this if needed
	}

	// Parse health check logs
	if err := ParseHealthLogs(dir, data); err != nil {
		// Non-fatal error, just skip if files don't exist
		// Could log this if needed
	}

	// Parse database diagnostics
	if err := ParseDatabaseDiagnostics(dir, data); err != nil {
		// Non-fatal error, just skip if files don't exist
		// Could log this if needed
	}

	return nil
}
