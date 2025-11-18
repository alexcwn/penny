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

	return nil
}
