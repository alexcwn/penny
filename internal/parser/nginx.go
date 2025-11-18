package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"penny/internal/models"
	"time"
)

// Nginx error log format: 2025/03/10 09:23:14 [error] 49140#101859: *4114 message...
var nginxRegex = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+)#(\d+):\s+(?:\*(\d+)\s+)?(.*)$`)

// ParseNginxErrorLog parses nginx error log format
func ParseNginxErrorLog(filePath string) ([]models.NginxLogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var entries []models.NginxLogEntry
	scanner := bufio.NewScanner(file)

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseNginxLine(line)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseNginxLine(line string) *models.NginxLogEntry {
	matches := nginxRegex.FindStringSubmatch(line)
	if matches == nil {
		// Couldn't parse, return with raw line
		return &models.NginxLogEntry{
			RawLine: line,
			Message: line,
		}
	}

	// Parse timestamp
	timestamp, _ := time.Parse("2006/01/02 15:04:05", matches[1])

	entry := &models.NginxLogEntry{
		Timestamp:    timestamp,
		Level:        strings.ToUpper(matches[2]),
		PID:          matches[3],
		TID:          matches[4],
		ConnectionID: matches[5],
		RawLine:      line,
	}

	// Parse the message part for additional fields
	message := matches[6]
	entry.Message = message

	// Extract common fields from message
	entry.Client = extractField(message, "client:")
	entry.Server = extractField(message, "server:")
	entry.Request = extractField(message, "request:")
	entry.Upstream = extractField(message, "upstream:")
	entry.Host = extractField(message, "host:")
	entry.Referrer = extractField(message, "referrer:")

	return entry
}

func extractField(message, prefix string) string {
	idx := strings.Index(message, prefix)
	if idx == -1 {
		return ""
	}

	start := idx + len(prefix)
	rest := message[start:]

	// Trim leading space
	rest = strings.TrimSpace(rest)

	// Find the end (next comma or end of string)
	end := strings.Index(rest, ",")
	if end == -1 {
		return strings.Trim(rest, `"`)
	}

	return strings.Trim(rest[:end], `"`)
}

// ParseNginxErrorLogs parses nginx error log from standard location
func ParseNginxErrorLogs(baseDir string) ([]models.NginxLogEntry, error) {
	nginxPath := filepath.Join(baseDir, "data", "log", "nginx-error.log")
	return ParseNginxErrorLog(nginxPath)
}
