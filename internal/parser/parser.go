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

	// Find and set the support archive creation timestamp
	creationTime, err := FindLatestSupportArchiveTime(dir)
	if err == nil && !creationTime.IsZero() {
		data.SystemInfo.CreationTimestamp = creationTime
	}

	return nil
}
