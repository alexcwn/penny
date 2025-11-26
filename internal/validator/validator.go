package validator

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed upgrade_rules.yaml
var upgradeRulesYAML string

// UpgradeRules holds the parsed upgrade path rules
type UpgradeRules struct {
	ValidUpgrades     map[string][]string `yaml:"valid_upgrades"`
	RecommendedPaths  map[string][]string `yaml:"recommended_paths"`
	DocsURLs          map[string]string   `yaml:"docs_urls"`
}

var (
	rules *UpgradeRules
	// Regex to extract version number (e.g., "23.4.1-01081507_B028E" -> "23.4.1")
	versionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)
)

// init loads and parses the embedded YAML at startup
func init() {
	rules = &UpgradeRules{}
	if err := yaml.Unmarshal([]byte(upgradeRulesYAML), rules); err != nil {
		panic(fmt.Sprintf("Failed to parse upgrade_rules.yaml: %v", err))
	}
}

// NormalizeVersion strips build hashes and extra identifiers from version strings
// Example: "23.4.1-01081507_B028E" -> "23.4.1"
func NormalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}
	return version
}

// IsValidUpgrade checks if upgrading from fromVersion to toVersion is valid
// Returns (isValid, errorMessage)
func IsValidUpgrade(fromVersion, toVersion string) (bool, string) {
	from := NormalizeVersion(fromVersion)
	to := NormalizeVersion(toVersion)

	// Empty versions are not valid
	if from == "" || to == "" {
		return false, "Empty version detected"
	}

	// Same version is not an upgrade
	if from == to {
		return false, fmt.Sprintf("Same version: %s", from)
	}

	// Check if fromVersion exists in our rules
	validTargets, exists := rules.ValidUpgrades[from]
	if !exists {
		return false, fmt.Sprintf("Unknown source version: %s", from)
	}

	// Check if toVersion is in the list of valid targets
	for _, validTarget := range validTargets {
		if to == validTarget {
			return true, ""
		}
	}

	// Not a valid direct upgrade - find recommended path
	recommendedPath := GetRecommendedPath(from, to)
	if recommendedPath != "" {
		return false, fmt.Sprintf("Invalid direct upgrade. Recommended path: %s", recommendedPath)
	}

	return false, fmt.Sprintf("No upgrade path found from %s to %s", from, to)
}

// GetRecommendedPath returns the recommended upgrade path from fromVersion to toVersion
// Returns a formatted string like "23.3.0 → 23.4.1 → 24.5.1 → 25.0.0"
func GetRecommendedPath(fromVersion, toVersion string) string {
	from := NormalizeVersion(fromVersion)
	to := NormalizeVersion(toVersion)

	// Check if we have a recommended path defined
	key := fmt.Sprintf("%s->%s", from, to)
	intermediateSteps, exists := rules.RecommendedPaths[key]

	if !exists {
		return ""
	}

	// Build the path: from → step1 → step2 → ... → to
	pathParts := []string{from}
	pathParts = append(pathParts, intermediateSteps...)
	pathParts = append(pathParts, to)

	return strings.Join(pathParts, " → ")
}

// ValidateUpgradePath validates an upgrade and returns a violation message if invalid
// Returns empty string if upgrade is valid
func ValidateUpgradePath(fromVersion, toVersion string) string {
	isValid, errMsg := IsValidUpgrade(fromVersion, toVersion)
	if isValid {
		return ""
	}
	return errMsg
}

// GetDocsURL returns the documentation URL for a given target version
func GetDocsURL(toVersion string) string {
	to := NormalizeVersion(toVersion)
	if url, exists := rules.DocsURLs[to]; exists {
		return url
	}
	return ""
}
