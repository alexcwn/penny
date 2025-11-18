package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"penny/internal/models"
)

// ParseProcessList parses ps aux output
func ParseProcessList(baseDir string, data *models.ArchiveData) error {
	processPath := filepath.Join(baseDir, "process_list.txt")

	file, err := os.Open(processPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var processes []models.Process
	scanner := bufio.NewScanner(file)

	// Skip header line
	firstLine := true

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Skip header
		if firstLine {
			firstLine = false
			continue
		}

		process := parseProcessLine(line)
		if process != nil {
			processes = append(processes, *process)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	data.Processes = processes
	return nil
}

func parseProcessLine(line string) *models.Process {
	// ps aux format (FreeBSD):
	// USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND

	fields := strings.Fields(line)
	if len(fields) < 11 {
		return nil
	}

	// Command is everything from field 10 onwards
	command := strings.Join(fields[10:], " ")

	return &models.Process{
		User:    fields[0],
		PID:     fields[1],
		CPU:     fields[2],
		Memory:  fields[3],
		VSZ:     fields[4],
		RSS:     fields[5],
		TT:      fields[6],
		Stat:    fields[7],
		Started: fields[8],
		Time:    fields[9],
		Command: command,
	}
}
