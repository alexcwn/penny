package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"penny/internal/models"
	"time"
)

// Nginx error log format: 2025/03/10 09:23:14 [error] 49140#101859: *4114 message...
var nginxErrorRegex = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+)#(\d+):\s+(?:\*(\d+)\s+)?(.*)$`)

// Nginx access log format: 10.56.206.2 - - [04/Aug/2025:13:25:02 +0900] "GET /api/... HTTP/1.1" 200 974 1578 "referer" "user-agent" 0.010
var nginxAccessRegex = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+([\d.]+)$`)

// ParseNginxErrorLog parses nginx error log format
func ParseNginxErrorLog(filePath string) ([]models.NginxLogEntry, error) {
	reader, err := openFileWithDecompression(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer reader.Close()

	return parseNginxErrorReader(reader)
}

// parseNginxErrorReader parses nginx error log from an io.Reader
func parseNginxErrorReader(reader io.Reader) ([]models.NginxLogEntry, error) {
	var entries []models.NginxLogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseNginxErrorLine(line)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseNginxErrorLine(line string) *models.NginxLogEntry {
	matches := nginxErrorRegex.FindStringSubmatch(line)
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

// ParseNginxErrorLogs parses all nginx error log files (including compressed rotated logs)
func ParseNginxErrorLogs(baseDir string) ([]models.NginxLogEntry, error) {
	logDir := filepath.Join(baseDir, "data", "log")
	var allEntries []models.NginxLogEntry

	// Parse rotated compressed logs in reverse order (oldest first: nginx-error.log.10 -> nginx-error.log.0)
	for i := 10; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("nginx-error.log.%d.bz2", i))
		if entries, err := ParseNginxErrorLog(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current uncompressed log last (newest)
	currentLogPath := filepath.Join(logDir, "nginx-error.log")
	if entries, err := ParseNginxErrorLog(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	return allEntries, nil
}

// ParseNginxAccessLog parses nginx access log format
func ParseNginxAccessLog(filePath string) ([]models.LogEntry, error) {
	reader, err := openFileWithDecompression(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer reader.Close()

	return parseNginxAccessReader(reader)
}

// parseNginxAccessReader parses nginx access log from an io.Reader
func parseNginxAccessReader(reader io.Reader) ([]models.LogEntry, error) {
	var entries []models.LogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseNginxAccessLine(line)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseNginxAccessLine(line string) *models.LogEntry {
	matches := nginxAccessRegex.FindStringSubmatch(line)
	if matches == nil {
		// Couldn't parse, return with raw line
		return &models.LogEntry{
			RawLine: line,
			Message: line,
		}
	}

	// Parse timestamp: 04/Aug/2025:13:25:02 +0900
	timestamp, _ := time.Parse("02/Jan/2006:15:04:05 -0700", matches[4])

	// Extract method from request
	requestParts := strings.Fields(matches[5])
	var method string
	if len(requestParts) >= 1 {
		method = requestParts[0]
	}

	entry := &models.LogEntry{
		Timestamp: timestamp,
		Hostname:  matches[1], // Client IP
		Process:   method,
		PID:       matches[6], // Status code
		Message:   matches[5], // Full request line
		Level:     determineAccessLogLevel(matches[6]),
		RawLine:   line,
	}

	return entry
}

// ParseNginxAccessLogs parses all nginx access log files (including compressed rotated logs)
func ParseNginxAccessLogs(baseDir string) ([]models.LogEntry, error) {
	logDir := filepath.Join(baseDir, "data", "log")
	var allEntries []models.LogEntry

	// Parse rotated compressed logs in reverse order (oldest first: nginx-access.log.10 -> nginx-access.log.0)
	for i := 10; i >= 0; i-- {
		logPath := filepath.Join(logDir, fmt.Sprintf("nginx-access.log.%d.bz2", i))
		if entries, err := ParseNginxAccessLog(logPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
		// Silently skip if file doesn't exist
	}

	// Parse current uncompressed log last (newest)
	currentLogPath := filepath.Join(logDir, "nginx-access.log")
	if entries, err := ParseNginxAccessLog(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort all entries by timestamp to ensure chronological order
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	return allEntries, nil
}

// determineAccessLogLevel returns log level based on HTTP status code
func determineAccessLogLevel(statusStr string) string {
	if len(statusStr) < 1 {
		return "INFO"
	}

	if statusStr[0] == '2' {
		return "INFO" // 2xx - success
	} else if statusStr[0] == '3' {
		return "INFO" // 3xx - redirect
	} else if statusStr[0] == '4' {
		return "WARNING" // 4xx - client error
	} else if statusStr[0] == '5' {
		return "ERROR" // 5xx - server error
	}

	return "INFO"
}
