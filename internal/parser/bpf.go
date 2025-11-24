package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"penny/internal/models"
	"sort"
	"strconv"
	"strings"
)

// ParseBPFStats parses BPF statistics files (netstat -B output)
func ParseBPFStats(baseDir string, data *models.ArchiveData) error {
	// Look for netstat files that contain BPF stats
	patterns := []string{
		"netstat*.txt",
		"netstat_sample*.txt",
	}

	var snapshots []models.BPFSnapshot

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(baseDir, pattern))
		if err != nil {
			continue
		}

		for _, filePath := range matches {
			snapshot, err := parseBPFFile(filePath)
			if err == nil && len(snapshot.Stats) > 0 {
				snapshots = append(snapshots, snapshot)
			}
		}
	}

	// Sort snapshots by filename (assumes timestamp ordering)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Filename < snapshots[j].Filename
	})

	data.BPFSnapshots = snapshots

	// Calculate comparisons between consecutive snapshots
	if len(snapshots) >= 2 {
		data.BPFComparisons = calculateBPFComparisons(snapshots)
	}

	return nil
}

// parseBPFFile parses a single BPF statistics file
func parseBPFFile(filePath string) (models.BPFSnapshot, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return models.BPFSnapshot{}, err
	}
	defer file.Close()

	snapshot := models.BPFSnapshot{
		Filename: filepath.Base(filePath),
		Stats:    []models.BPFStat{},
	}

	scanner := bufio.NewScanner(file)
	headerFound := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Look for header line
		if strings.Contains(line, "Pid") && strings.Contains(line, "Netif") {
			headerFound = true
			continue
		}

		// Parse data lines after header
		if headerFound {
			stat := parseBPFLine(line)
			if stat.Interface != "" {
				stat.SnapshotID = snapshot.Filename
				snapshot.Stats = append(snapshot.Stats, stat)
			}
		}
	}

	return snapshot, scanner.Err()
}

// parseBPFLine parses a single line of BPF statistics
// Format:   Pid  Netif   Flags      Recv      Drop     Match Sblen Hblen Command
// Example: 26594  port1 p--s--- 547624939         0 547624939  9366     0 n2os_ids
func parseBPFLine(line string) models.BPFStat {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return models.BPFStat{}
	}

	stat := models.BPFStat{
		Interface: fields[1],
		Flags:     fields[2],
		Command:   fields[8],
	}

	// Parse numeric fields
	if pid, err := strconv.Atoi(fields[0]); err == nil {
		stat.PID = pid
	}
	if recv, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
		stat.Recv = recv
	}
	if drop, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
		stat.Drop = drop
	}
	if match, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
		stat.Match = match
	}
	if sblen, err := strconv.ParseInt(fields[6], 10, 64); err == nil {
		stat.Sblen = sblen
	}
	if hblen, err := strconv.ParseInt(fields[7], 10, 64); err == nil {
		stat.Hblen = hblen
	}

	return stat
}

// calculateBPFComparisons calculates deltas between consecutive snapshots
func calculateBPFComparisons(snapshots []models.BPFSnapshot) []models.BPFComparison {
	var comparisons []models.BPFComparison

	for i := 0; i < len(snapshots)-1; i++ {
		snapshot1 := snapshots[i]
		snapshot2 := snapshots[i+1]

		// Assume 5 seconds between snapshots (common pattern)
		// Could be enhanced to parse actual timestamps from filenames
		timeDelta := 5.0

		// Create a map of stats from snapshot1 for easy lookup
		statsMap := make(map[string]models.BPFStat)
		for _, stat := range snapshot1.Stats {
			key := stat.Interface + "_" + strconv.Itoa(stat.PID)
			statsMap[key] = stat
		}

		// Compare each stat in snapshot2 with snapshot1
		for _, stat2 := range snapshot2.Stats {
			key := stat2.Interface + "_" + strconv.Itoa(stat2.PID)
			if stat1, found := statsMap[key]; found {
				comp := models.BPFComparison{
					Interface:  stat2.Interface,
					PID:        stat2.PID,
					Command:    stat2.Command,
					RecvDelta:  stat2.Recv - stat1.Recv,
					DropDelta:  stat2.Drop - stat1.Drop,
					MatchDelta: stat2.Match - stat1.Match,
					SblenDelta: stat2.Sblen - stat1.Sblen,
					HblenDelta: stat2.Hblen - stat1.Hblen,
					TimeDelta:  timeDelta,
				}

				// Calculate rates (packets per second)
				if timeDelta > 0 {
					comp.RecvRate = float64(comp.RecvDelta) / timeDelta
					comp.DropRate = float64(comp.DropDelta) / timeDelta
				}

				// Calculate drop percentage
				if comp.RecvDelta > 0 {
					comp.DropPercentage = (float64(comp.DropDelta) / float64(comp.RecvDelta)) * 100
				}

				// Calculate buffer growth percentage
				if stat1.Sblen > 0 {
					comp.BufferGrowth = ((float64(stat2.Sblen) - float64(stat1.Sblen)) / float64(stat1.Sblen)) * 100
				}

				// Mark as having issues if drops occurred or significant buffer growth
				comp.HasIssue = comp.DropDelta > 0 || comp.BufferGrowth > 200

				// Only include comparisons with non-zero activity or issues
				if comp.RecvDelta > 0 || comp.DropDelta > 0 || comp.HasIssue {
					comparisons = append(comparisons, comp)
				}
			}
		}
	}

	return comparisons
}
