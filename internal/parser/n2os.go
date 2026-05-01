package parser

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"penny/internal/models"
)

// ParseN2OSConfig parses the n2os.conf.user file
func ParseN2OSConfig(baseDir string, data *models.ArchiveData) error {
	configPath := filepath.Join(resolveCfgDir(baseDir), "n2os.conf.user")

	// Read raw content
	rawContent, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, not an error
		}
		return err
	}

	data.N2OSConfig.RawContent = string(rawContent)

	// Parse settings
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	var settings []models.N2OSSetting
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		setting := parseN2OSLine(line)
		if setting != nil {
			settings = append(settings, *setting)
		}
	}

	data.N2OSConfig.Settings = settings

	// Extract timezone and hardware model from settings
	timezone := "UTC" // Default to UTC if not found
	for _, setting := range settings {
		switch setting.Key {
		case "system time tz":
			timezone = setting.Value
		case "system hardware_model":
			if data.SystemInfo.Platform == "" {
				data.SystemInfo.Platform = setting.Value
				data.Metadata.Platform = setting.Value
			}
		}
	}
	data.SystemInfo.Timezone = timezone

	// Parse CMC configuration
	data.SystemInfo.CMCConfig = parseCMCConfig(settings)

	return scanner.Err()
}

// parseCMCConfig extracts CMC configuration from n2os settings
func parseCMCConfig(settings []models.N2OSSetting) models.CMCConfig {
	config := models.CMCConfig{
		HasConfig: false,
		// Default sync-conf to true (enabled by default)
		SyncConfVariables:     true,
		SyncConfPhysicalLinks: true,
		SyncConfNodes:         true,
		SyncConfLinks:         true,
	}

	for _, setting := range settings {
		// Skip non-CMC settings and token-related settings
		if !strings.HasPrefix(setting.Key, "cmc") {
			continue
		}

		// Skip token fields
		if strings.Contains(setting.Key, "token") {
			continue
		}

		config.HasConfig = true

		// Parse specific CMC settings
		switch {
		case setting.Key == "cmc sync-to":
			// Extract URL from "!https://..." format
			config.SyncTo = strings.TrimPrefix(setting.Value, "!")
			// Remove any trailing token/UUID
			parts := strings.Fields(config.SyncTo)
			if len(parts) > 0 {
				config.SyncTo = parts[0]
			}

		case setting.Key == "cmc sync send_only_visible_alert":
			if setting.Value == "true" {
				config.SyncMode = "Send Only Visible Alerts"
			} else {
				config.SyncMode = "Send All Alerts"
			}

		case setting.Key == "cmc multi-context":
			config.MultiContext = setting.Value == "true"

		case setting.Key == "cmc send_bundle_without_updating":
			config.SendBundleWithoutUpdating = setting.Value == "true"

		case setting.Key == "cmc sync-conf variables":
			config.SyncConfVariables = setting.Value != "false"

		case setting.Key == "cmc sync-conf physical_links":
			config.SyncConfPhysicalLinks = setting.Value != "false"

		case setting.Key == "cmc sync-conf nodes":
			config.SyncConfNodes = setting.Value != "false"

		case setting.Key == "cmc sync-conf links":
			config.SyncConfLinks = setting.Value != "false"

		case setting.Key == "cmc proxy-conf":
			// Parse JSON proxy configuration
			parseProxyConfig(&config, setting.Value)
		}
	}

	return config
}

// parseProxyConfig parses the JSON proxy configuration
func parseProxyConfig(config *models.CMCConfig, jsonStr string) {
	var proxyData struct {
		Enabled     bool   `json:"enabled"`
		Host        string `json:"host"`
		Port        string `json:"port"`
		AuthEnabled bool   `json:"auth_enabled"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &proxyData); err != nil {
		return // Silently ignore parse errors
	}

	config.ProxyEnabled = proxyData.Enabled
	config.ProxyHost = proxyData.Host
	config.ProxyPort = proxyData.Port
	config.ProxyAuthEnabled = proxyData.AuthEnabled
}

func parseN2OSLine(line string) *models.N2OSSetting {
	// Split by spaces to handle multi-word keys like "license base"
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	var key, value string

	// Special handling for multi-word keys
	if parts[0] == "license" && len(parts) >= 3 {
		// "license base value" or "license asset_intelligence value"
		key = parts[0] + " " + parts[1]
		value = strings.Join(parts[2:], " ")
	} else if parts[0] == "system" && len(parts) >= 4 && parts[1] == "time" && parts[2] == "tz" {
		// "system time tz Asia/Tokyo"
		key = parts[0] + " " + parts[1] + " " + parts[2]
		value = strings.Join(parts[3:], " ")
	} else if parts[0] == "system" && len(parts) >= 3 {
		// "system hardware_model NS1" or other two-word system keys
		key = parts[0] + " " + parts[1]
		value = strings.Join(parts[2:], " ")
	} else if parts[0] == "cmc" && len(parts) >= 3 {
		// "cmc sync-to value" or "cmc sync-conf nodes true"
		if parts[1] == "sync-conf" && len(parts) >= 4 {
			// "cmc sync-conf nodes true" -> key: "cmc sync-conf nodes", value: "true"
			key = parts[0] + " " + parts[1] + " " + parts[2]
			value = strings.Join(parts[3:], " ")
		} else if parts[1] == "sync" && len(parts) >= 4 {
			// "cmc sync send_only_visible_alert true" -> key: "cmc sync send_only_visible_alert", value: "true"
			key = parts[0] + " " + parts[1] + " " + parts[2]
			value = strings.Join(parts[3:], " ")
		} else {
			// "cmc sync-to value" or "cmc multi-context value"
			key = parts[0] + " " + parts[1]
			value = strings.Join(parts[2:], " ")
		}
	} else {
		// Standard key value format
		key = parts[0]
		value = strings.Join(parts[1:], " ")
	}

	// No masking - show everything as-is
	isSensitive := false
	maskedValue := value

	// Get documentation
	description, docsURL := getSettingDocs(key)

	return &models.N2OSSetting{
		Key:         key,
		Value:       value,
		MaskedValue: maskedValue,
		IsSensitive: isSensitive,
		Description: description,
		DocsURL:     docsURL,
	}
}

func getSettingDocs(key string) (string, string) {
	// Documentation for common settings
	docs := map[string]struct {
		description string
		url         string
	}{
		"vi": {
			"Visibility Intelligence settings",
			"https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html",
		},
		"system": {
			"System-level configuration",
			"https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html",
		},
		"cmc": {
			"Central Management Console settings",
			"https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html",
		},
		"license": {
			"License configuration",
			"https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html",
		},
		"alerts": {
			"Alert system configuration",
			"https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html",
		},
	}

	// Try to match by prefix
	for prefix, info := range docs {
		if strings.HasPrefix(key, prefix) {
			return info.description, info.url
		}
	}

	// Default
	return "Configuration setting", "https://technicaldocs.nozominetworks.com/products/n2os/topics/administration/settings/features/c_n2os_admin_settings_features_guardian.html"
}
