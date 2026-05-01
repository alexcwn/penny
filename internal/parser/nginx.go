package parser

import (
	"bufio"
	"compress/bzip2"
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

// extractBz2InPlace extracts a .bz2 file to the same directory (removing .bz2 extension)
// Returns the path to the extracted file. If the file is already extracted, returns the path without extracting.
func extractBz2InPlace(bz2Path string) (string, error) {
	// Determine output path by removing .bz2 extension
	if !strings.HasSuffix(bz2Path, ".bz2") {
		return "", fmt.Errorf("file does not have .bz2 extension: %s", bz2Path)
	}
	extractedPath := strings.TrimSuffix(bz2Path, ".bz2")

	// Check if already extracted
	if _, err := os.Stat(extractedPath); err == nil {
		// File already exists, return it
		return extractedPath, nil
	}

	// Open compressed file
	srcFile, err := os.Open(bz2Path)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()

	// Create output file
	outFile, err := os.Create(extractedPath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	// Decompress
	reader := bzip2.NewReader(srcFile)
	_, err = io.Copy(outFile, reader)
	if err != nil {
		os.Remove(extractedPath) // Clean up on error
		return "", err
	}

	return extractedPath, nil
}

// Nginx error log format: 2025/03/10 09:23:14 [error] 49140#101859: *4114 message...
var nginxErrorRegex = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+)#(\d+):\s+(?:\*(\d+)\s+)?(.*)$`)

// Nginx access log format: 10.56.206.2 - - [04/Aug/2025:13:25:02 +0900] "GET /api/... HTTP/1.1" 200 974 1578 "referer" "user-agent" 0.010
var nginxAccessRegex = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+([\d.]+)$`)

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

	// Extract filename from path for Source field
	filename := filepath.Base(filePath)
	return parseNginxErrorReader(file, filename)
}

// parseNginxErrorReader parses nginx error log from an io.Reader
func parseNginxErrorReader(reader io.Reader, source string) ([]models.NginxLogEntry, error) {
	var entries []models.NginxLogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseNginxErrorLine(line, source, lineNumber)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseNginxErrorLine(line string, source string, lineNumber int) *models.NginxLogEntry {
	matches := nginxErrorRegex.FindStringSubmatch(line)
	if matches == nil {
		// Couldn't parse, return with raw line
		return &models.NginxLogEntry{
			RawLine:    line,
			Message:    line,
			Source:     source,
			LineNumber: lineNumber,
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
		Source:       source,
		LineNumber:   lineNumber,
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
	logDir := resolveLogDir(baseDir)
	var allEntries []models.NginxLogEntry

	// Parse rotated compressed logs in reverse order (oldest first: nginx-error.log.10 -> nginx-error.log.0)
	for i := 10; i >= 0; i-- {
		bz2Path := filepath.Join(logDir, fmt.Sprintf("nginx-error.log.%d.bz2", i))
		if _, err := os.Stat(bz2Path); os.IsNotExist(err) {
			continue // Skip if doesn't exist
		}

		// Extract .bz2 in place (or use existing extracted file)
		extractedPath, err := extractBz2InPlace(bz2Path)
		if err != nil {
			continue // Skip on error
		}

		// Parse extracted file
		if entries, err := ParseNginxErrorLog(extractedPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	// Parse current uncompressed log
	currentLogPath := filepath.Join(logDir, "nginx-error.log")
	if entries, err := ParseNginxErrorLog(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort by timestamp
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
	})

	return allEntries, nil
}

// ParseNginxAccessLog parses nginx access log format
func ParseNginxAccessLog(filePath string) ([]models.LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	// Extract filename from path for Source field
	filename := filepath.Base(filePath)
	return parseNginxAccessReader(file, filename)
}

// parseNginxAccessReader parses nginx access log from an io.Reader
func parseNginxAccessReader(reader io.Reader, source string) ([]models.LogEntry, error) {
	var entries []models.LogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := parseNginxAccessLine(line, source, lineNumber)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return entries, err
	}

	return entries, nil
}

func parseNginxAccessLine(line string, source string, lineNumber int) *models.LogEntry {
	matches := nginxAccessRegex.FindStringSubmatch(line)
	if matches == nil {
		// Couldn't parse, return with raw line
		return &models.LogEntry{
			RawLine:    line,
			Message:    line,
			Source:     source,
			LineNumber: lineNumber,
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
		Timestamp:  timestamp,
		Hostname:   matches[1], // Client IP
		Process:    method,
		PID:        matches[6], // Status code
		Message:    matches[5], // Full request line
		Level:      determineAccessLogLevel(matches[6]),
		RawLine:    line,
		Source:     source,
		LineNumber: lineNumber,
	}

	return entry
}

// ParseNginxAccessLogs parses all nginx access log files (including compressed rotated logs)
func ParseNginxAccessLogs(baseDir string) ([]models.LogEntry, error) {
	logDir := resolveLogDir(baseDir)
	var allEntries []models.LogEntry

	// Parse rotated compressed logs in reverse order (oldest first: nginx-access.log.10 -> nginx-access.log.0)
	for i := 10; i >= 0; i-- {
		bz2Path := filepath.Join(logDir, fmt.Sprintf("nginx-access.log.%d.bz2", i))
		if _, err := os.Stat(bz2Path); os.IsNotExist(err) {
			continue // Skip if doesn't exist
		}

		// Extract .bz2 in place (or use existing extracted file)
		extractedPath, err := extractBz2InPlace(bz2Path)
		if err != nil {
			continue // Skip on error
		}

		// Parse extracted file
		if entries, err := ParseNginxAccessLog(extractedPath); err == nil {
			allEntries = append(allEntries, entries...)
		}
	}

	// Parse current uncompressed log
	currentLogPath := filepath.Join(logDir, "nginx-access.log")
	if entries, err := ParseNginxAccessLog(currentLogPath); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Sort by timestamp
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
