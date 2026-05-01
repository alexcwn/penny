package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"strconv"
	"strings"
	"time"
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

	// Parse machine ID
	if machineID, err := readFile(filepath.Join(baseDir, "machineid.txt")); err == nil {
		data.SystemInfo.MachineID = strings.TrimSpace(machineID)
	}

	if applianceUUID, err := readFile(filepath.Join(resolveCfgDir(baseDir), ".appliance-uuid")); err == nil {
		data.SystemInfo.ApplianceUUID = strings.TrimSpace(applianceUUID)
	}

	// Parse asset metrics from meta.json
	if err := parseMetaJSON(baseDir, data); err == nil {
		// Successfully parsed meta.json
	}

	// Parse licenses from licenses.json
	if err := parseLicensesJSON(baseDir, data); err == nil {
		// Successfully parsed licenses.json
	}

	// Parse sysctl.txt for hardware metrics
	if err := parseSysctl(baseDir, data); err == nil {
		// Successfully parsed sysctl.txt
	}

	// Get creation time from n2os.conf.gz last modified time
	n2osConfPath := filepath.Join(resolveCfgDir(baseDir), "n2os.conf.gz")
	if fileInfo, err := os.Stat(n2osConfPath); err == nil {
		// Convert to UTC
		data.SystemInfo.CreationTimestamp = fileInfo.ModTime().UTC()
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

	// Parse resolv.conf for DNS servers
	if dns := parseResolvConf(baseDir); dns != "" {
		data.NetworkConfig.DNS = dns
	}

	_ = ParseNetstatDrops(baseDir, data)
	_ = ParseNetstatRoutes(baseDir, data)

	return nil
}

// ParseNetstatDrops parses netstat_drops.txt into NetworkConfig.NetstatDrops
func ParseNetstatDrops(baseDir string, data *models.ArchiveData) error {
	path := filepath.Join(baseDir, "netstat_drops.txt")
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "Name") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 13 {
			continue
		}
		entry := models.NetstatDropEntry{
			Name:    strPtr(fields[0]),
			Mtu:     strPtr(fields[1]),
			Network: strPtr(fields[2]),
			Address: strPtr(fields[3]),
			Ipkts:   strPtr(fields[4]),
			Ierrs:   strPtr(fields[5]),
			Idrop:   strPtr(fields[6]),
			Ibytes:  strPtr(fields[7]),
			Opkts:   strPtr(fields[8]),
			Oerrs:   strPtr(fields[9]),
			Obytes:  strPtr(fields[10]),
			Coll:    strPtr(fields[11]),
			Drop:    strPtr(fields[12]),
		}
		data.NetworkConfig.NetstatDrops = append(data.NetworkConfig.NetstatDrops, entry)
	}
	return scanner.Err()
}

func strPtr(s string) *string {
	return &s
}

// ParseNetstatRoutes parses netstat_routing.txt into NetworkConfig.NetstatRoutes
func ParseNetstatRoutes(baseDir string, data *models.ArchiveData) error {
	path := filepath.Join(baseDir, "netstat_routing.txt")
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "Routing") ||
			strings.HasPrefix(trimmed, "Internet") ||
			strings.HasPrefix(trimmed, "Destination") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		entry := models.NetstatRouteEntry{
			Destination: strPtr(fields[0]),
			Gateway:     strPtr(fields[1]),
			Flags:       strPtr(fields[2]),
			Netif:       strPtr(fields[3]),
		}
		if len(fields) >= 5 {
			entry.Expire = strPtr(fields[4])
		}
		data.NetworkConfig.NetstatRoutes = append(data.NetworkConfig.NetstatRoutes, entry)
	}
	return scanner.Err()
}

// parseResolvConf parses resolv.conf for DNS nameservers
func parseResolvConf(baseDir string) string {
	resolvPath := filepath.Join(baseDir, "resolv.conf")

	file, err := os.Open(resolvPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var nameservers []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Look for nameserver entries
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			}
		}
	}

	if len(nameservers) == 0 {
		return ""
	}

	// Join with " / " separator
	return strings.Join(nameservers, " / ")
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

// parseDiskUsage parses diskusage.txt content into structured entries
func parseDiskUsage(content string) []models.DiskUsageEntry {
	var entries []models.DiskUsageEntry

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split by tab or multiple spaces
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		size := fields[0]
		path := strings.Join(fields[1:], " ")

		// Convert size to bytes for sorting (inline to avoid duplicate function)
		sizeBytes := convertDiskSizeToBytes(size)

		entries = append(entries, models.DiskUsageEntry{
			Size:      size,
			SizeBytes: sizeBytes,
			Path:      path,
		})
	}

	return entries
}

// convertDiskSizeToBytes converts size strings like "15G", "4.7G", "604M" to bytes
func convertDiskSizeToBytes(size string) int64 {
	size = strings.TrimSpace(size)
	if size == "" {
		return 0
	}

	// Get the suffix (last character)
	suffix := size[len(size)-1:]
	var multiplier int64 = 1

	switch suffix {
	case "K", "k":
		multiplier = 1024
		size = size[:len(size)-1]
	case "M", "m":
		multiplier = 1024 * 1024
		size = size[:len(size)-1]
	case "G", "g":
		multiplier = 1024 * 1024 * 1024
		size = size[:len(size)-1]
	case "T", "t":
		multiplier = 1024 * 1024 * 1024 * 1024
		size = size[:len(size)-1]
	}

	// Parse the numeric part
	value, err := strconv.ParseFloat(size, 64)
	if err != nil {
		return 0
	}

	return int64(value * float64(multiplier))
}

// ParseStorage parses storage information
func ParseStorage(baseDir string, data *models.ArchiveData) error {
	// Parse zpool status
	zpoolPath := filepath.Join(baseDir, "zpool_status.txt")
	if zpools, err := parseZpoolStatus(zpoolPath); err == nil {
		data.Storage.ZpoolStatus = zpools
	}

	// Parse disk usage
	diskUsagePath := filepath.Join(baseDir, "diskusage.txt")
	if usage, err := readFile(diskUsagePath); err == nil {
		data.Storage.DiskUsageRaw = usage
		// Parse the diskusage entries
		data.Storage.DiskUsage = parseDiskUsage(usage)
	}

	// Parse disk free
	if free, err := readFile(filepath.Join(baseDir, "diskfree.txt")); err == nil {
		data.Storage.DiskFree = free
	}

	// Parse SMART data
	passMap := parseCamcontrolPassMap(filepath.Join(baseDir, "camcontrol_devlist.txt"))
	if disks, err := parseSmartctl(filepath.Join(baseDir, "smartctl.txt"), passMap); err == nil {
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

// splitPoolBlocks splits raw zpool_status.txt content into one string per pool block
func splitPoolBlocks(content string) []string {
	var blocks []string
	var current []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "pool:") && current != nil {
			blocks = append(blocks, strings.Join(current, "\n"))
			current = nil
		}
		current = append(current, line)
	}
	if current != nil {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

func parseZpoolStatus(path string) ([]models.ZpoolStatus, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}

	// Pre-compute raw output per pool block by splitting on "pool:" boundaries
	poolRawBlocks := splitPoolBlocks(content)

	var zpools []models.ZpoolStatus
	var currentPool *models.ZpoolStatus
	poolIndex := -1

	lines := strings.Split(content, "\n")
	inConfig := false
	inErrors := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "pool:") {
			if currentPool != nil {
				zpools = append(zpools, *currentPool)
			}
			poolIndex++
			currentPool = &models.ZpoolStatus{
				Pool: strings.TrimSpace(strings.TrimPrefix(trimmed, "pool:")),
			}
			if poolIndex < len(poolRawBlocks) {
				currentPool.RawOutput = poolRawBlocks[poolIndex]
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

// parseCamcontrolPassMap parses camcontrol_devlist.txt and returns a map from
// pass device number to the primary device name, e.g. "pass0" -> "ada0".
func parseCamcontrolPassMap(path string) map[string]string {
	m := make(map[string]string)
	content, err := readFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(content, "\n") {
		// Lines look like: <Model ...>   at scbus... (ada0,pass0)
		start := strings.LastIndex(line, "(")
		end := strings.LastIndex(line, ")")
		if start == -1 || end <= start {
			continue
		}
		devs := strings.Split(line[start+1:end], ",")
		// Find the pass device and map it to the first non-pass device
		var primary, passdev string
		for _, d := range devs {
			d = strings.TrimSpace(d)
			if strings.HasPrefix(d, "pass") {
				passdev = d
			} else if primary == "" {
				primary = d
			}
		}
		if passdev != "" && primary != "" {
			m[passdev] = primary
		}
	}
	return m
}

func parseSmartctl(path string, passMap map[string]string) ([]models.DiskInfo, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var disks []models.DiskInfo
	var currentDisk *models.DiskInfo
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// New smartctl command starts — match "smartctl -a /dev/..." only, not the version banner
		if strings.HasPrefix(trimmed, "smartctl") && strings.Contains(trimmed, "/dev/") {
			if currentDisk != nil && currentDisk.Model != "" {
				finalizeSmartDisk(currentDisk)
				disks = append(disks, *currentDisk)
			}
			currentDisk = &models.DiskInfo{}

			// Extract device from command line
			if strings.Contains(trimmed, "/dev/") {
				parts := strings.Fields(trimmed)
				for _, part := range parts {
					if strings.HasPrefix(part, "/dev/") {
						// Resolve /dev/pass* via camcontrol map; fall back to the pass name if unmapped
						if strings.HasPrefix(part, "/dev/pass") {
							passName := strings.TrimPrefix(part, "/dev/")
							if primary, ok := passMap[passName]; ok {
								currentDisk.Device = "/dev/" + primary
							} else {
								currentDisk.Device = part
							}
						} else {
							currentDisk.Device = part
						}
						break
					}
				}
			}
		} else if currentDisk != nil {
			if strings.HasPrefix(trimmed, "Device Model:") {
				currentDisk.Model = strings.TrimSpace(strings.TrimPrefix(trimmed, "Device Model:"))
			} else if strings.HasPrefix(trimmed, "Product:") {
				// SCSI/VM disks report Product: instead of Device Model:
				currentDisk.Model = strings.TrimSpace(strings.TrimPrefix(trimmed, "Product:"))
			} else if strings.HasPrefix(trimmed, "Serial Number:") {
				currentDisk.Serial = strings.TrimSpace(strings.TrimPrefix(trimmed, "Serial Number:"))
			} else if strings.HasPrefix(trimmed, "User Capacity:") {
				raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "User Capacity:"))
				// Extract human-readable size from brackets, e.g. "[64.0 GB, 59.6 GiB]" or "[1.09 TB]"
				if start := strings.Index(raw, "["); start != -1 {
					if end := strings.Index(raw, "]"); end != -1 {
						bracket := raw[start+1 : end] // e.g. "64.0 GB, 59.6 GiB" or "1.09 TB"
						// Use only the first unit (before comma)
						first := strings.SplitN(bracket, ",", 2)[0]
						currentDisk.Capacity = strings.TrimSpace(first) // e.g. "64.0 GB" or "1.09 TB"
					}
				}
				if currentDisk.Capacity == "" {
					currentDisk.Capacity = raw // fallback to full string
				}
				// Parse CapacityGB: handle both GB and TB
				if strings.Contains(raw, " GB") {
					if start := strings.Index(raw, "["); start != -1 {
						if end := strings.Index(raw[start:], " GB"); end != -1 {
							gbStr := strings.ReplaceAll(strings.TrimSpace(raw[start+1:start+end]), ",", "")
							if gb, err := strconv.ParseFloat(gbStr, 64); err == nil {
								currentDisk.CapacityGB = int(gb)
							}
						}
					}
				} else if strings.Contains(raw, " TB") {
					if start := strings.Index(raw, "["); start != -1 {
						if end := strings.Index(raw[start:], " TB"); end != -1 {
							tbStr := strings.ReplaceAll(strings.TrimSpace(raw[start+1:start+end]), ",", "")
							if tb, err := strconv.ParseFloat(tbStr, 64); err == nil {
								currentDisk.CapacityGB = int(tb * 1024)
							}
						}
					}
				}
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
			} else if strings.HasPrefix(trimmed, "SMART support is:") {
				// Only set true on the availability line; ignore subsequent "Enabled" line
				if strings.Contains(trimmed, "Available - device has SMART capability.") {
					currentDisk.SMARTAvailable = true
				}
			} else {
				// Parse SMART attribute table rows by leading attribute ID
				fields := strings.Fields(trimmed)
				if len(fields) >= 10 {
					switch fields[0] {
					case "169":
						if v, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil {
							currentDisk.RemainingLifePct = int(v)
						}
					case "241":
						if v, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil {
							currentDisk.HostWritesLBA = v
						}
					case "242":
						if v, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil {
							currentDisk.HostReadsLBA = v
						}
					}
				}
			}
		}
	}

	if currentDisk != nil && currentDisk.Device != "" && currentDisk.Model != "" {
		finalizeSmartDisk(currentDisk)
		disks = append(disks, *currentDisk)
	}

	return disks, nil
}

// finalizeSmartDisk computes derived health fields after a disk block has been fully parsed.
func finalizeSmartDisk(d *models.DiskInfo) {
	if !d.SMARTAvailable {
		d.DiskHealthStatus = "VM"
		return
	}

	// Remaining lifetime check (attr 169) — only flag if attr was actually present (non-zero)
	if d.RemainingLifePct > 100 || (d.RemainingLifePct > 0 && d.RemainingLifePct < 20) {
		d.LifetimeCritical = true
	}

	// Write cycles (attr 241 formula)
	if d.CapacityGB > 0 && d.HostWritesLBA > 0 {
		d.WriteCycles = int((d.HostWritesLBA * 32 / 1024) / int64(d.CapacityGB))
	}

	// Device-specific threshold
	if limit, ok := models.DiskWriteCycleLimits[d.Model]; ok {
		d.WriteCycleLimit = limit
		if d.WriteCycles > limit {
			d.CyclesExceeded = true
		}
	}

	// Final verdict
	switch {
	case d.LifetimeCritical && d.RemainingLifePct > 100:
		d.DiskHealthStatus = "FRIED"
	case d.LifetimeCritical || d.CyclesExceeded:
		d.DiskHealthStatus = "Critical"
	case d.RemainingLifePct > 0 || d.HostWritesLBA > 0:
		d.DiskHealthStatus = "Healthy"
	default:
		d.DiskHealthStatus = "Unknown"
	}
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

// parseMetaJSON parses the meta.json file containing asset metrics
func parseMetaJSON(baseDir string, data *models.ArchiveData) error {
	metaPath := filepath.Join(resolveCfgDir(baseDir), "meta.json")

	content, err := os.ReadFile(metaPath)
	if err != nil {
		return err
	}

	// Define a struct to unmarshal the JSON
	var meta struct {
		Nodes     string `json:"nodes"`
		Links     string `json:"links"`
		Variables string `json:"variables"`
	}

	if err := json.Unmarshal(content, &meta); err != nil {
		return err
	}

	// Convert string values to integers
	if nodes, err := strconv.Atoi(meta.Nodes); err == nil {
		data.SystemInfo.TotalNodes = nodes
	}
	if links, err := strconv.Atoi(meta.Links); err == nil {
		data.SystemInfo.TotalLinks = links
	}
	if variables, err := strconv.Atoi(meta.Variables); err == nil {
		data.SystemInfo.TotalVariables = variables
	}

	return nil
}

// parseLicensesJSON parses the licenses.json file containing license information
func parseLicensesJSON(baseDir string, data *models.ArchiveData) error {
	licensesPath := filepath.Join(baseDir, "health_check", "licenses.json")

	file, err := os.Open(licensesPath)
	if err != nil {
		return err
	}
	defer file.Close()

	var licenses []models.License
	scanner := bufio.NewScanner(file)

	// Read each line as a separate JSON object (NDJSON format)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Define a struct to unmarshal the JSON
		var rawLicense struct {
			Licensee   string `json:"licensee"`
			Type       string `json:"type"`
			Status     string `json:"status"`
			Bundle     string `json:"bundle_name"`
			Purpose    string `json:"purpose"`
			IsDisabled bool   `json:"is_disabled"`
			Extra      struct {
				ExpireDate          string `json:"expire_date"`
				ActualLicensedNodes string `json:"actual_licensed_nodes"`
				SupportedNodes      string `json:"supported_nodes"`
			} `json:"extra"`
		}

		if err := json.Unmarshal([]byte(line), &rawLicense); err != nil {
			continue // Skip malformed lines
		}

		license := models.License{
			Licensee:            rawLicense.Licensee,
			Type:                rawLicense.Type,
			Status:              rawLicense.Status,
			BundleName:          rawLicense.Bundle,
			Purpose:             rawLicense.Purpose,
			IsDisabled:          rawLicense.IsDisabled,
			ActualLicensedNodes: rawLicense.Extra.ActualLicensedNodes,
			SupportedNodes:      rawLicense.Extra.SupportedNodes,
		}

		// Parse expiredate from Unix milliseconds
		if rawLicense.Extra.ExpireDate != "" {
			if millis, err := strconv.ParseInt(rawLicense.Extra.ExpireDate, 10, 64); err == nil && millis > 0 {
				seconds := millis / 1000
				nanos := (millis % 1000) * 1000000
				license.ExpireDate = time.Unix(seconds, nanos).UTC()
			}
		}

		licenses = append(licenses, license)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	data.SystemInfo.Licenses = licenses
	return nil
}

// parseSysctl parses sysctl.txt for key hardware and system metrics
func parseSysctl(baseDir string, data *models.ArchiveData) error {
	sysctlPath := filepath.Join(baseDir, "sysctl.txt")

	file, err := os.Open(sysctlPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inMsgbuf := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Handle multi-line kern.msgbuf (contains boot messages)
		if strings.HasPrefix(line, "kern.msgbuf:") {
			inMsgbuf = true
			continue
		}

		// If we're in msgbuf, skip until we see a top-level sysctl key again.
		// Sysctl keys start at column 0 and look like "word.word...: value".
		// Msgbuf content lines are either indented or don't contain a dot before the colon.
		if inMsgbuf {
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				if idx := strings.Index(line, ": "); idx > 0 {
					key := line[:idx]
					if strings.Contains(key, ".") && !strings.Contains(key, " ") {
						inMsgbuf = false
						// Fall through to parse this line as a key-value pair
					}
				}
			}
			if inMsgbuf {
				continue
			}
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "hw.model":
			data.SystemInfo.CPUModel = value

		case "hw.physmem":
			data.SystemInfo.AvailableMemory = value

		case "hw.realmem":
			data.SystemInfo.PhysicalMemory = value

		case "kern.smp.cpus":
			if cores, err := strconv.Atoi(value); err == nil {
				data.SystemInfo.CPUCores = cores
			}

		case "kern.boottime":
			// Format: { sec = 1759803800, usec = 4163 } Tue Oct  7 11:23:20 2025
			if idx := strings.Index(value, "sec = "); idx != -1 {
				secStr := value[idx+6:]
				if commaIdx := strings.Index(secStr, ","); commaIdx != -1 {
					secStr = secStr[:commaIdx]
					if sec, err := strconv.ParseInt(secStr, 10, 64); err == nil {
						data.SystemInfo.BootTime = time.Unix(sec, 0).UTC()
					}
				}
			}
		}
	}

	return scanner.Err()
}
