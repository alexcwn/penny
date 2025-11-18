package parser

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"penny/internal/models"
)

// ParseN2OSConfig parses the n2os.conf.user file
func ParseN2OSConfig(baseDir string, data *models.ArchiveData) error {
	configPath := filepath.Join(baseDir, "data", "cfg", "n2os.conf.user")

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
	return scanner.Err()
}

func parseN2OSLine(line string) *models.N2OSSetting {
	// Split by spaces to handle multi-word keys like "license base"
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	var key, value string

	// Special handling for license lines: "license base value" or "license asset_intelligence value"
	if parts[0] == "license" && len(parts) >= 3 {
		key = parts[0] + " " + parts[1] // "license base" or "license asset_intelligence"
		value = strings.Join(parts[2:], " ")
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
