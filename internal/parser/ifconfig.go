package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"penny/internal/models"
	"regexp"
	"strings"
)

// Regex patterns for ifconfig parsing
var (
	interfaceLineRegex = regexp.MustCompile(`^(\S+):\s+flags=([0-9a-f]+)<([^>]+)>\s+(.*)`)
	optionsRegex       = regexp.MustCompile(`^\s+options=([0-9a-f]+)<([^>]+)>`)
	etherRegex         = regexp.MustCompile(`^\s+ether\s+([0-9a-f:]+)`)
	inetRegex          = regexp.MustCompile(`^\s+inet\s+(\S+)\s+netmask\s+(0x[0-9a-f]+)(?:\s+broadcast\s+(\S+))?`)
	mediaRegex         = regexp.MustCompile(`^\s+media:\s+(.+)`)
	statusRegex        = regexp.MustCompile(`^\s+status:\s+(.+)`)
	mtuRegex           = regexp.MustCompile(`mtu\s+(\d+)`)
	metricRegex        = regexp.MustCompile(`metric\s+(\d+)`)
)

// ParseIfconfig parses ifconfig output
func ParseIfconfig(filePath string) ([]models.NetworkInterface, string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}

	rawContent := string(content)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, rawContent, err
	}
	defer file.Close()

	var interfaces []models.NetworkInterface
	var currentInterface *models.NetworkInterface
	var currentBlock strings.Builder

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check if this is a new interface line
		if matches := interfaceLineRegex.FindStringSubmatch(line); matches != nil {
			// Save previous interface
			if currentInterface != nil {
				currentInterface.RawIfconfigBlock = currentBlock.String()
				interfaces = append(interfaces, *currentInterface)
			}

			// Start new interface
			currentBlock.Reset()
			currentBlock.WriteString(line + "\n")

			name := matches[1]
			flagsHex := matches[2]
			flagsStr := matches[3]
			rest := matches[4]

			flags := strings.Split(flagsStr, ",")

			currentInterface = &models.NetworkInterface{
				Name:       name,
				Flags:      flags,
				FlagsCount: len(flags),
				FlagsHex:   flagsHex,
			}

			// Extract MTU and metric from rest
			if mtuMatch := mtuRegex.FindStringSubmatch(rest); mtuMatch != nil {
				currentInterface.MTU = mtuMatch[1]
			}
			if metricMatch := metricRegex.FindStringSubmatch(rest); metricMatch != nil {
				currentInterface.Metric = metricMatch[1]
			}

		} else if currentInterface != nil {
			currentBlock.WriteString(line + "\n")

			// Parse interface properties
			if matches := optionsRegex.FindStringSubmatch(line); matches != nil {
				currentInterface.Options = matches[2]
				currentInterface.OptionsHex = matches[1]

			} else if matches := etherRegex.FindStringSubmatch(line); matches != nil {
				currentInterface.MACAddress = matches[1]

			} else if matches := inetRegex.FindStringSubmatch(line); matches != nil {
				currentInterface.IPAddress = matches[1]
				currentInterface.NetmaskHex = matches[2]
				currentInterface.NetmaskDecimal = hexNetmaskToDecimal(matches[2])
				if len(matches) > 3 && matches[3] != "" {
					currentInterface.Broadcast = matches[3]
				}

			} else if matches := mediaRegex.FindStringSubmatch(line); matches != nil {
				currentInterface.Media = strings.TrimSpace(matches[1])

			} else if matches := statusRegex.FindStringSubmatch(line); matches != nil {
				currentInterface.Status = strings.TrimSpace(matches[1])
			}
		}
	}

	// Save last interface
	if currentInterface != nil {
		currentInterface.RawIfconfigBlock = currentBlock.String()
		interfaces = append(interfaces, *currentInterface)
	}

	return interfaces, rawContent, scanner.Err()
}

// ParseIfconfigWithMapping parses ifconfig and applies physical interface mapping from rc.conf
func ParseIfconfigWithMapping(baseDir string, rcConf map[string]string) ([]models.NetworkInterface, string, error) {
	ifconfigPath := filepath.Join(baseDir, "ifconfig.txt")
	interfaces, rawContent, err := ParseIfconfig(ifconfigPath)
	if err != nil {
		return nil, rawContent, err
	}

	// Build reverse mapping: logical name -> physical name
	// Pattern: ifconfig_igb0_name="mgmt" means igb0 -> mgmt, so mgmt should show (igb0)
	physicalToLogical := make(map[string]string)
	namePattern := regexp.MustCompile(`^ifconfig_(\w+)_name$`)

	for key, value := range rcConf {
		if matches := namePattern.FindStringSubmatch(key); matches != nil {
			physicalName := matches[1] // e.g., "igb0"
			logicalName := value       // e.g., "mgmt"
			physicalToLogical[logicalName] = physicalName
		}
	}

	// Apply mapping to interfaces
	for i := range interfaces {
		if physicalName, exists := physicalToLogical[interfaces[i].Name]; exists {
			interfaces[i].PhysicalName = physicalName
		}
	}

	return interfaces, rawContent, nil
}

// hexNetmaskToDecimal converts hex netmask to dotted decimal
func hexNetmaskToDecimal(hexMask string) string {
	// Remove 0x prefix
	hexMask = strings.TrimPrefix(hexMask, "0x")

	// Parse hex string to uint32
	if len(hexMask) != 8 {
		return ""
	}

	var octets [4]byte
	for i := 0; i < 4; i++ {
		val := 0
		fmt.Sscanf(hexMask[i*2:i*2+2], "%x", &val)
		octets[i] = byte(val)
	}

	return fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
}
