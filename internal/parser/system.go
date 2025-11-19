package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"strings"
)

// ParseSystemInfo parses system information files
func ParseSystemInfo(baseDir string, data *models.ArchiveData) error {
	// Parse product from rc.conf
	data.SystemInfo.Product = detectProduct(baseDir)

	// Parse version
	if version, err := readFile(filepath.Join(baseDir, "version.txt")); err == nil {
		data.SystemInfo.Version = strings.TrimSpace(version)
		data.Metadata.Version = strings.TrimSpace(version)
	}

	// Parse platform
	if platform, err := readFile(filepath.Join(baseDir, "platform.txt")); err == nil {
		data.SystemInfo.Platform = strings.TrimSpace(platform)
		data.Metadata.Platform = strings.TrimSpace(platform)
	}

	// Parse uptime
	if uptime, err := readFile(filepath.Join(baseDir, "uptime.txt")); err == nil {
		data.SystemInfo.Uptime = strings.TrimSpace(uptime)
	}

	// Parse hostname from rc.conf
	if hostname := parseHostnameFromRcConf(baseDir); hostname != "" {
		data.SystemInfo.Hostname = hostname
		data.Metadata.Hostname = hostname
	}

	return nil
}

// ParseNetworkConfig parses network configuration files
func ParseNetworkConfig(baseDir string, data *models.ArchiveData) error {
	rcConfPath := filepath.Join(baseDir, "rc.conf")

	rcConf, err := parseRcConf(rcConfPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	data.NetworkConfig.RcConf = rcConf

	// Extract hostname
	if hostname, ok := rcConf["hostname"]; ok {
		data.NetworkConfig.Hostname = hostname
	}

	// Extract default gateway
	if gw, ok := rcConf["defaultrouter"]; ok {
		data.NetworkConfig.DefaultGW = gw
	}

	// Parse ifconfig with mapping
	interfaces, rawIfconfig, err := ParseIfconfigWithMapping(baseDir, rcConf)
	if err != nil {
		// If ifconfig parsing fails, fall back to rc.conf extraction
		interfaces = extractInterfaces(rcConf)
	} else {
		// Merge ifconfig data with rc.conf data
		interfaces = mergeInterfaceData(interfaces, rcConf)
	}

	data.NetworkConfig.Interfaces = interfaces
	data.NetworkConfig.RawIfconfigData = rawIfconfig

	return nil
}

// mergeInterfaceData merges ifconfig data with rc.conf configuration
func mergeInterfaceData(ifconfigInterfaces []models.NetworkInterface, rcConf map[string]string) []models.NetworkInterface {
	// For each interface, try to add the rc.conf config line
	for i := range ifconfigInterfaces {
		// Try to find matching rc.conf line
		configKey := "ifconfig_" + ifconfigInterfaces[i].Name
		if config, ok := rcConf[configKey]; ok {
			ifconfigInterfaces[i].Config = config
		}
	}
	return ifconfigInterfaces
}

// ParseStorage parses storage information
func ParseStorage(baseDir string, data *models.ArchiveData) error {
	// Parse zpool status
	zpoolPath := filepath.Join(baseDir, "zpool_status.txt")
	if zpools, err := parseZpoolStatus(zpoolPath); err == nil {
		data.Storage.ZpoolStatus = zpools
	}

	// Parse disk usage
	if usage, err := readFile(filepath.Join(baseDir, "diskusage.txt")); err == nil {
		data.Storage.DiskUsage = usage
	}

	// Parse disk free
	if free, err := readFile(filepath.Join(baseDir, "diskfree.txt")); err == nil {
		data.Storage.DiskFree = free
	}

	// Parse SMART data
	if disks, err := parseSmartctl(filepath.Join(baseDir, "smartctl.txt")); err == nil {
		data.Storage.DiskInfo = disks
	}

	// Parse fstab
	if fstab, err := parseFstab(filepath.Join(baseDir, "fstab.txt")); err == nil {
		data.Storage.Fstab = fstab
	}

	// Parse ZFS list
	if zfsList, err := parseZfsList(filepath.Join(baseDir, "zfs_list.txt")); err == nil {
		data.Storage.ZfsList = zfsList
	}

	return nil
}

func detectProduct(baseDir string) string {
	rcConfPath := filepath.Join(baseDir, "rc.conf")
	content, err := readFile(rcConfPath)
	if err != nil {
		return "Guardian" // Default if can't read file
	}

	// Check for CMC indicator
	if strings.Contains(content, `n2osids_if="cmc"`) {
		return "CMC"
	}

	return "Guardian"
}

func parseRcConf(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value or key="value"
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			config[key] = value
		}
	}

	return config, scanner.Err()
}

func parseHostnameFromRcConf(baseDir string) string {
	rcConfPath := filepath.Join(baseDir, "rc.conf")
	rcConf, err := parseRcConf(rcConfPath)
	if err != nil {
		return ""
	}
	return rcConf["hostname"]
}

func extractInterfaces(rcConf map[string]string) []models.NetworkInterface {
	var interfaces []models.NetworkInterface

	for key, value := range rcConf {
		// Look for ifconfig_* entries
		if strings.HasPrefix(key, "ifconfig_") {
			// Extract interface name
			name := strings.TrimPrefix(key, "ifconfig_")

			// Skip name assignments (like ifconfig_igb0_name)
			if strings.HasSuffix(name, "_name") {
				continue
			}

			iface := models.NetworkInterface{
				Name:   name,
				Config: value,
			}

			// Try to extract IP and netmask
			if strings.Contains(value, "inet ") {
				parts := strings.Fields(value)
				for i, part := range parts {
					if part == "inet" && i+1 < len(parts) {
						iface.IPAddress = parts[i+1]
					}
					if part == "netmask" && i+1 < len(parts) {
						iface.Netmask = parts[i+1]
					}
				}
			}

			interfaces = append(interfaces, iface)
		}
	}

	return interfaces
}

func parseZpoolStatus(path string) ([]models.ZpoolStatus, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var zpools []models.ZpoolStatus
	var currentPool *models.ZpoolStatus

	lines := strings.Split(content, "\n")
	inConfig := false
	inErrors := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "pool:") {
			if currentPool != nil {
				zpools = append(zpools, *currentPool)
			}
			currentPool = &models.ZpoolStatus{
				Pool: strings.TrimSpace(strings.TrimPrefix(trimmed, "pool:")),
			}
			inConfig = false
			inErrors = false
		} else if currentPool != nil {
			if strings.HasPrefix(trimmed, "state:") {
				currentPool.State = strings.TrimSpace(strings.TrimPrefix(trimmed, "state:"))
			} else if strings.HasPrefix(trimmed, "status:") {
				currentPool.Status = strings.TrimSpace(strings.TrimPrefix(trimmed, "status:"))
			} else if strings.HasPrefix(trimmed, "scan:") {
				currentPool.Scan = strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))
			} else if strings.HasPrefix(trimmed, "config:") {
				inConfig = true
				inErrors = false
			} else if strings.HasPrefix(trimmed, "errors:") {
				currentPool.Errors = strings.TrimSpace(strings.TrimPrefix(trimmed, "errors:"))
				inConfig = false
				inErrors = true
			} else if inErrors {
				// Continue collecting error lines (file paths)
				if trimmed != "" {
					currentPool.Errors += "\n" + trimmed
				}
			} else if inConfig && trimmed != "" && !strings.HasPrefix(trimmed, "NAME") {
				// Parse device line
				fields := strings.Fields(trimmed)
				if len(fields) >= 5 {
					device := models.ZpoolDevice{
						Name:  fields[0],
						State: fields[1],
						Read:  fields[2],
						Write: fields[3],
						Cksum: fields[4],
					}
					currentPool.Config = append(currentPool.Config, device)
				}
			} else if !inConfig && !inErrors {
				// Multi-line status continuation
				if currentPool.Status != "" && trimmed != "" && !strings.HasPrefix(trimmed, "action:") && !strings.HasPrefix(trimmed, "see:") {
					currentPool.Status += " " + trimmed
				}
			}
		}
	}

	if currentPool != nil {
		zpools = append(zpools, *currentPool)
	}

	return zpools, nil
}

func parseSmartctl(path string) ([]models.DiskInfo, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var disks []models.DiskInfo
	var currentDisk *models.DiskInfo
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// New smartctl command starts
		if strings.HasPrefix(trimmed, "smartctl") {
			if currentDisk != nil {
				disks = append(disks, *currentDisk)
			}
			currentDisk = &models.DiskInfo{}

			// Extract device from command line
			if strings.Contains(trimmed, "/dev/") {
				parts := strings.Fields(trimmed)
				for _, part := range parts {
					if strings.HasPrefix(part, "/dev/") {
						currentDisk.Device = part
						break
					}
				}
			}
		} else if currentDisk != nil {
			if strings.HasPrefix(trimmed, "Device Model:") {
				currentDisk.Model = strings.TrimSpace(strings.TrimPrefix(trimmed, "Device Model:"))
			} else if strings.HasPrefix(trimmed, "Serial Number:") {
				currentDisk.Serial = strings.TrimSpace(strings.TrimPrefix(trimmed, "Serial Number:"))
			} else if strings.HasPrefix(trimmed, "User Capacity:") {
				currentDisk.Capacity = strings.TrimSpace(strings.TrimPrefix(trimmed, "User Capacity:"))
			} else if strings.Contains(trimmed, "overall-health") && strings.Contains(trimmed, "PASSED") {
				currentDisk.Health = "PASSED"
			} else if strings.Contains(trimmed, "overall-health") && strings.Contains(trimmed, "FAILED") {
				currentDisk.Health = "FAILED"
			} else if strings.Contains(trimmed, "Temperature_Celsius") {
				fields := strings.Fields(trimmed)
				if len(fields) > 9 {
					currentDisk.Temperature = fields[9]
				}
			} else if strings.Contains(trimmed, "Power_On_Hours") {
				fields := strings.Fields(trimmed)
				if len(fields) > 9 {
					currentDisk.PowerOnHours = fields[9]
				}
			}
		}
	}

	if currentDisk != nil && currentDisk.Device != "" {
		disks = append(disks, *currentDisk)
	}

	return disks, nil
}

func parseFstab(path string) ([]models.FstabEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []models.FstabEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			entry := models.FstabEntry{
				Device:     fields[0],
				MountPoint: fields[1],
				FSType:     fields[2],
				Options:    fields[3],
			}
			if len(fields) >= 5 {
				entry.Dump = fields[4]
			}
			if len(fields) >= 6 {
				entry.Pass = fields[5]
			}
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

func parseZfsList(path string) ([]models.ZfsDataset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var datasets []models.ZfsDataset
	scanner := bufio.NewScanner(file)

	// Skip header line
	firstLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if firstLine {
			firstLine = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			dataset := models.ZfsDataset{
				Name:       fields[0],
				Used:       fields[1],
				Available:  fields[2],
				Refer:      fields[3],
				MountPoint: fields[4],
			}

			// Calculate usage percentage
			dataset.UsedPercent = calculateZfsUsage(fields[1], fields[2])

			datasets = append(datasets, dataset)
		}
	}

	return datasets, scanner.Err()
}

func calculateZfsUsage(used, available string) float64 {
	usedBytes := parseZfsSize(used)
	availBytes := parseZfsSize(available)

	if usedBytes == 0 && availBytes == 0 {
		return 0
	}

	total := usedBytes + availBytes
	if total == 0 {
		return 0
	}

	return (float64(usedBytes) / float64(total)) * 100
}

func parseZfsSize(size string) int64 {
	// Parse ZFS sizes like "1.5G", "256M", "10.2T"
	size = strings.TrimSpace(size)
	if size == "-" || size == "0" {
		return 0
	}

	multipliers := map[byte]int64{
		'K': 1024,
		'M': 1024 * 1024,
		'G': 1024 * 1024 * 1024,
		'T': 1024 * 1024 * 1024 * 1024,
	}

	if len(size) == 0 {
		return 0
	}

	lastChar := size[len(size)-1]
	if multiplier, ok := multipliers[lastChar]; ok {
		// Has unit suffix
		numStr := size[:len(size)-1]
		if num, err := parseFloat(numStr); err == nil {
			return int64(num * float64(multiplier))
		}
	}

	// No suffix, assume bytes
	if num, err := parseFloat(size); err == nil {
		return int64(num)
	}

	return 0
}

func parseFloat(s string) (float64, error) {
	var result float64
	_, err := fmt.Sscanf(s, "%f", &result)
	return result, err
}

func readFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
