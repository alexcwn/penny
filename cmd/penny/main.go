package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"penny/internal/extractor"
	"penny/internal/models"
	"penny/internal/parser"
	"penny/internal/pennyconfig"
	"penny/internal/server"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var version = "dev"

// MagicNumber represents a file signature
type MagicNumber struct {
	Offset int
	Bytes  []byte
	Type   string
}

// Common magic numbers for file types
var magicNumbers = []MagicNumber{
	// Images
	{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG image"},
	{0, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG image"},
	{0, []byte{0x47, 0x49, 0x46, 0x38}, "GIF image"},
	{0, []byte{0x42, 0x4D}, "BMP image"},
	{0, []byte{0x49, 0x49, 0x2A, 0x00}, "TIFF image (little-endian)"},
	{0, []byte{0x4D, 0x4D, 0x00, 0x2A}, "TIFF image (big-endian)"},
	{0, []byte{0x38, 0x42, 0x50, 0x53}, "Photoshop image"},

	// Archives
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP archive"},
	{0, []byte{0x50, 0x4B, 0x05, 0x06}, "ZIP archive (empty)"},
	{0, []byte{0x50, 0x4B, 0x07, 0x08}, "ZIP archive (spanned)"},
	{0, []byte{0x1F, 0x8B, 0x08}, "GZIP archive"},
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip archive"},
	{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "RAR archive"},
	{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "RAR archive (v5)"},
	{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ archive"},
	//{0, []byte{0x75, 0x73, 0x74, 0x61, 0x72}, "TAR archive"},
	{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ archive"},
	{0, []byte{0x75, 0x73, 0x74, 0x61, 0x72}, "TAR archive (ustar)"},
	{257, []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00}, "POSIX TAR archive"},
	{257, []byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}, "GNU TAR archive"},
	// POSIX tar archive detection at offset 0 with specific pattern
	{0, []byte{0x2E, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "POSIX TAR archive"},

	// Documents
	{0, []byte{0x25, 0x50, 0x44, 0x46}, "PDF document"},
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Microsoft Office document"},
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "Microsoft Office 2007+ document"},
	{0, []byte{0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31}, "RTF document"},

	// Audio/Video
	{0, []byte{0x49, 0x44, 0x33}, "MP3 audio"},
	{0, []byte{0xFF, 0xFB}, "MP3 audio (no ID3)"},
	{0, []byte{0xFF, 0xF3}, "MP3 audio (no ID3)"},
	{0, []byte{0xFF, 0xF2}, "MP3 audio (no ID3)"},
	{0, []byte{0x52, 0x49, 0x46, 0x46}, "WAV/AVI/WebP file"},
	{0, []byte{0x1A, 0x45, 0xDF, 0xA3}, "WebM/Matroska video"},
	{0, []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, "MP4 video"},
	{0, []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, "MP4 video"},
	{0, []byte{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70}, "MP4 video"},
	{0, []byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, "MP4 video"},
	{0, []byte{0x4F, 0x67, 0x67, 0x53}, "OGG audio/video"},
	{0, []byte{0x46, 0x4C, 0x56, 0x01}, "FLV video"},

	// Executables
	{0, []byte{0x4D, 0x5A}, "Windows executable"},
	{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O executable"},
	{0, []byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O executable"},
	{0, []byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O executable"},
	{0, []byte{0xCA, 0xFE, 0xBA, 0xBE}, "Java class file"},

	// Text and Data
	{0, []byte{0xEF, 0xBB, 0xBF}, "UTF-8 with BOM"},
	{0, []byte{0xFF, 0xFE}, "UTF-16 (little-endian)"},
	{0, []byte{0xFE, 0xFF}, "UTF-16 (big-endian)"},
	{0, []byte{0x00, 0x00, 0xFE, 0xFF}, "UTF-32 (big-endian)"},
	{0, []byte{0xFF, 0xFE, 0x00, 0x00}, "UTF-32 (little-endian)"},

	// Database
	{0, []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66}, "SQLite database"},

	// Disk Images
	{0, []byte{0x45, 0x52, 0x02, 0x00, 0x00, 0x00}, "ISO disk image"},
	{0, []byte{0x44, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00}, "DMG disk image"},
}

func main() {
	// Define CLI flags
	setup := flag.Bool("setup", false, "Start setup page only (no archive required)")
	archiveFile := flag.String("f", "", "Optional. Archive file path (.tbz2|.nozomini_backup)")
	outputDir := flag.String("o", "", "Output directory for extraction")
	analyzeDir := flag.String("d", "", "Directory to analyze (existing extraction)")
	port := flag.Int("port", 8080, "Optional. HTTP server port")

	flag.Parse()

	if *setup {
		runSetupMode(*port)
		return
	}

	// Validate flags
	if *archiveFile != "" && *analyzeDir != "" {
		log.Fatal("Error: Cannot specify both -f (archive) and -d (directory)")
	}

	if *archiveFile == "" && *analyzeDir == "" {
		printUsage()
		os.Exit(1)
	}

	var targetDir string

	// Handle archive extraction mode
	if *archiveFile != "" {
		// Check if archive exists
		if _, err := os.Stat(*archiveFile); os.IsNotExist(err) {
			log.Fatalf("Error: Archive file '%s' does not exist", *archiveFile)
		}

		// Check if file is a POSIX TAR archive
		if !isSupportedArchive(*archiveFile) {
			log.Fatal("Error: Not a valid Support Archive compressed file.")
		}

		// Determine output directory
		if *outputDir == "" {
			targetDir = promptForDirectory(*archiveFile)
		} else {
			targetDir = *outputDir
		}

		// Check if output directory already exists
		if _, err := os.Stat(targetDir); err == nil {
			log.Fatalf("Error: Directory '%s' already exists. Use -d to analyze existing directory.", targetDir)
		}

		// Extract archive
		fmt.Printf("Extracting %s to %s...\n", *archiveFile, targetDir)
		if err := extractor.Extract(*archiveFile, targetDir); err != nil {
			log.Fatalf("Error extracting archive: %v", err)
		}
		fmt.Println("Extraction complete.")

		// Detect archive type before validating
		if detectArchiveType(targetDir) == "backup" {
			runBackupMode(*port, targetDir)
			return
		}

		// Validate support archive structure
		if err := validateSupportArchive(targetDir); err != nil {
			log.Fatal(err)
		}
	} else {
		// Analyze existing directory mode
		targetDir = *analyzeDir

		// Check if directory exists
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			log.Fatalf("Error: Directory '%s' does not exist", targetDir)
		}

		// Detect archive type before validating
		if detectArchiveType(targetDir) == "backup" {
			runBackupMode(*port, targetDir)
			return
		}

		// Validate support archive structure
		if err := validateSupportArchive(targetDir); err != nil {
			log.Fatal(err)
		}
	}

	// Parse the archive data
	fmt.Printf("Parsing data from %s...\n", targetDir)
	data, err := parseArchive(targetDir)
	if err != nil {
		log.Fatalf("Error parsing archive: %v", err)
	}

	// Run start_analysis.sh if present (non-interactive copy, blocking lines stripped)
	runStartAnalysis(targetDir)

	// Run post_analysis.py if it exists and is executable
	runPostAnalysis(targetDir)

	// Run hc_upgrade_path.sh if it exists and is executable
	runHCUpgradePath(targetDir, data)

	// Run hc_disks.sh if it exists and is executable
	runHCDisks(targetDir, data)

	// Load ~/.penny/penny.yaml: run BYOS scripts and resolve landing view
	runPennyConfig(targetDir, data)

	// Index logs into SQLite (blocking — handlers depend on this DB)
	fmt.Printf("Indexing logs...\n")
	if err := parser.IndexLogs(targetDir, data); err != nil {
		log.Printf("Warning: log indexing failed: %v", err)
	}

	// Open the log DB for handler use, then free log slices from memory
	logsDBPath := filepath.Join(targetDir, ".penny", "penny_logs.db")
	logsDB, err := sql.Open("sqlite", logsDBPath+"?_journal_mode=WAL&_cache_size=-65536")
	if err != nil {
		log.Printf("Warning: could not open log db: %v", err)
	} else {
		server.SetLogsDB(logsDB)
	}

	// Free log slices from memory — data now lives in SQLite
	data.Logs.Messages = nil
	data.Logs.NginxErrors = nil
	data.Logs.NginxAccess = nil
	data.Logs.AuthLog = nil
	data.N2OpLogs = nil
	data.N2OSJobLogs = nil
	data.N2OSProductionLogs = nil
	data.N2OSMigrateLogs = nil
	data.N2OSIDSLogs = nil
	data.N2OSIDSEventsLogs = nil
	data.N2OSAlertLogs = nil
	data.N2OSAlertEventsLogs = nil
	data.HealthEvents = nil

	// Start web server
	url := fmt.Sprintf("http://localhost:%d/#%s", *port, data.LandingView)
	fmt.Printf("\nStarting server on %s\n", url)
	fmt.Println("Press Ctrl+C to stop")

	// Open browser after a short delay to let the server start
	fmt.Printf("Opening %s in your browser...\n", url)
	go openBrowser(url)

	if err := server.Start(*port, data, version); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

// isSupportedArchive checks if the file is a supported archive (TAR or gzip-compressed TAR)
func isSupportedArchive(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Warning: Could not open file for magic number check: %v", err)
		return false
	}
	defer file.Close()

	// Read the first 512 bytes to check for signatures
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		log.Printf("Warning: Could not read file for magic number check: %v", err)
		return false
	}

	// Accept gzip magic bytes (covers .tar.gz, .nozomi_backup, etc.)
	if n >= 2 && buffer[0] == 0x1f && buffer[1] == 0x8b {
		return true
	}

	// Check for POSIX TAR archive magic numbers
	for _, magic := range magicNumbers {
		if magic.Type == "POSIX TAR archive" {
			if magic.Offset+len(magic.Bytes) <= n {
				match := true
				for i, b := range magic.Bytes {
					if buffer[magic.Offset+i] != b {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}

	return false
}

func runBackupMode(port int, dir string) {
	fmt.Printf("Backup archive detected: %s\n", dir)
	dump, err := parser.ParseBackupDump(dir)
	if err != nil {
		log.Fatalf("Error parsing backup dump: %v", err)
	}
	server.SetBackupData(dump)

	// Parse and index logs from log/n2os/
	fmt.Printf("Parsing data from %s...\n", dir)
	data, err := parseArchive(dir)
	if err != nil {
		log.Printf("Warning: error parsing archive data: %v", err)
		data = &models.ArchiveData{}
	}

	fmt.Printf("Indexing logs...\n")
	if err := parser.IndexLogs(dir, data); err != nil {
		log.Printf("Warning: log indexing failed: %v", err)
	}

	logsDBPath := filepath.Join(dir, ".penny", "penny_logs.db")
	logsDB, err := sql.Open("sqlite", logsDBPath+"?_journal_mode=WAL&_cache_size=-65536")
	if err != nil {
		log.Printf("Warning: could not open log db: %v", err)
	} else {
		server.SetLogsDB(logsDB)
	}

	url := fmt.Sprintf("http://localhost:%d/", port)
	fmt.Printf("\nStarting server on %s\n", url)
	fmt.Println("Press Ctrl+C to stop")
	go openBrowser(url)
	if err := server.Start(port, data, version); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func detectArchiveType(dir string) string {
	hasFile := func(rel string) bool {
		_, err := os.Stat(filepath.Join(dir, rel))
		return err == nil
	}

	hasCfg := hasFile("cfg")
	hasDump := false
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dump-") {
			hasDump = true
			break
		}
	}
	hasRRD := hasFile("rrd")

	if hasCfg && hasDump && hasRRD {
		return "backup"
	}

	if hasFile("version.txt") && hasFile("start_analysis.sh") &&
		hasFile("sysctl.txt") && hasFile("kenv.txt") &&
		hasFile(filepath.Join("data", "cfg", "n2os.conf.user")) {
		return "support"
	}

	return "unknown"
}

func validateSupportArchive(dir string) error {
	requiredFiles := []string{
		filepath.Join("data", "cfg", "n2os.conf.gz"),
		filepath.Join("data", "cfg", "n2os.conf.user"),
		filepath.Join("data", "log", "n2os", "n2os_ids.log"),
		filepath.Join("data", "log", "n2os", "n2osjobs.log"),
		filepath.Join("data", "log", "messages"),
	}

	for _, relPath := range requiredFiles {
		fullPath := filepath.Join(dir, relPath)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("Not a valid support archive...")
		}
	}

	return nil
}

func promptForDirectory(archiveFile string) string {
	base := filepath.Base(archiveFile)
	// Strip all known archive extensions
	for _, ext := range []string{".nozomi_backup", ".tbz2", ".tar.bz2", ".tgz", ".tar.gz", ".tar"} {
		if strings.HasSuffix(base, ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	defaultDir := strings.ReplaceAll(base, " ", "_")

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Extract to directory [default: %s]: ", defaultDir)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultDir
	}
	return input
}

func parseArchive(dir string) (*models.ArchiveData, error) {
	data := &models.ArchiveData{
		Metadata: models.ArchiveMetadata{
			ExtractedPath: dir,
		},
	}

	// Parse system info files
	fmt.Printf("  %s system information...", parser.GetRandomVerb())
	err := parser.ParseSystemInfo(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing system info: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse logs
	fmt.Printf("  %s log files...\n", parser.GetRandomVerb())
	err = parser.ParseLogs(dir, data)
	if err != nil {
		fmt.Printf("  ❌\n")
		log.Printf("Warning: Error parsing logs: %v", err)
	} else {
		fmt.Printf("  ✅\n")
	}

	// Parse process list
	fmt.Printf("  %s process list...", parser.GetRandomVerb())
	err = parser.ParseProcessList(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing process list: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse network config
	fmt.Printf("  %s network configuration...", parser.GetRandomVerb())
	err = parser.ParseNetworkConfig(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing network config: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse BPF statistics
	fmt.Printf("  %s BPF statistics...", parser.GetRandomVerb())
	err = parser.ParseBPFStats(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing BPF stats: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse storage info
	fmt.Printf("  %s storage information...", parser.GetRandomVerb())
	err = parser.ParseStorage(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing storage info: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2OS config
	fmt.Printf("  %s N2OS configuration...", parser.GetRandomVerb())
	err = parser.ParseN2OSConfig(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing N2OS config: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	// Parse N2Op logs for upgrade history
	fmt.Printf("  %s N2Op upgrade logs...", parser.GetRandomVerb())
	err = parser.ParseN2OpLogs(dir, data)
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: Error parsing N2Op logs: %v", err)
	} else {
		fmt.Printf(" ✅\n")
	}

	return data, nil
}

// runStartAnalysis reads start_analysis.sh from the archive dir, strips interactive/blocking lines,
// writes a temp copy, executes it from the archive dir, then cleans up the temp file.
func runStartAnalysis(targetDir string) {
	// If both output files already exist, skip running the script
	logAnalysisDir := filepath.Join(targetDir, "health_check", "log_analysis")
	outputAnalysisExists := func() bool {
		_, err := os.Stat(filepath.Join(logAnalysisDir, "output_analysis.out"))
		return err == nil
	}()
	goAccessExists := func() bool {
		_, err := os.Stat(filepath.Join(logAnalysisDir, "goaccess-out.html"))
		return err == nil
	}()
	if outputAnalysisExists && goAccessExists {
		fmt.Printf("  Running start_analysis.sh... . ✅\n")
		return
	}

	scriptPath := filepath.Join(targetDir, "start_analysis.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		return // Not present, skip silently
	}

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		log.Printf("Warning: could not read start_analysis.sh: %v", err)
		return
	}

	// Strip specific blocking lines: the interactive read and the macOS open call
	var filtered []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "open ${GOACCESS_OUTPUT_FILE}") ||
			strings.Contains(line, "read -r KEEP_TEMP_FILES") {
			continue
		}
		filtered = append(filtered, line)
	}

	tmp, err := os.CreateTemp("", "start_analysis_*.sh")
	if err != nil {
		log.Printf("Warning: could not create temp script: %v", err)
		return
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(strings.Join(filtered, "\n")); err != nil {
		tmp.Close()
		log.Printf("Warning: could not write temp script: %v", err)
		return
	}
	tmp.Close()

	if err := os.Chmod(tmp.Name(), 0700); err != nil {
		log.Printf("Warning: could not chmod temp script: %v", err)
		return
	}

	fmt.Printf("  Running start_analysis.sh...")
	cmd := exec.Command(tmp.Name())
	cmd.Dir = targetDir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: start_analysis.sh failed: %v\nstderr: %s", err, stderr.String())
		return
	}
	fmt.Printf(" ✅\n")
}

// runPostAnalysis reads post_analysis.py from the TSE_ToolKit, strips the webbrowser.open line,
// writes a temp copy, executes it with python3 from the archive dir, then cleans up.
func runPostAnalysis(targetDir string) {
	// If post_analysis.html already exists, skip running the script
	postAnalysisPath := filepath.Join(targetDir, "health_check", "log_analysis", "post_analysis.html")
	if _, err := os.Stat(postAnalysisPath); err == nil {
		fmt.Printf("  Running post_analysis.py... . ✅\n")
		return
	}

	scriptPath, err := exec.LookPath("post_analysis.py")
	if err != nil {
		return // Not in $PATH, skip silently
	}

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		log.Printf("Warning: could not read post_analysis.py: %v", err)
		return
	}

	// Strip the line that opens the browser
	var filtered []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "webbrowser.open(") {
			continue
		}
		filtered = append(filtered, line)
	}

	tmp, err := os.CreateTemp("", "post_analysis_*.py")
	if err != nil {
		log.Printf("Warning: could not create temp script: %v", err)
		return
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(strings.Join(filtered, "\n")); err != nil {
		tmp.Close()
		log.Printf("Warning: could not write temp script: %v", err)
		return
	}
	tmp.Close()

	fmt.Printf("  Running post_analysis.py...")
	cmd := exec.Command("python3", tmp.Name(), targetDir)
	cmd.Dir = targetDir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: post_analysis.py failed: %v\nstderr: %s", err, stderr.String())
		return
	}
	fmt.Printf(" ✅\n")
}

// runHCDisks checks if hc_disks.sh exists and is executable, runs it from the archive dir, and stores the output
func runHCDisks(targetDir string, data *models.ArchiveData) {
	scriptPath, err := exec.LookPath("hc_disks.sh")
	if err != nil {
		return // Not in $PATH, skip silently
	}

	if _, err := os.Stat(filepath.Join(targetDir, "smartctl.txt")); err != nil {
		return // Required log file not present, skip silently
	}

	fmt.Printf("  Stealing Savario's Disks analysis...")
	cmd := exec.Command(scriptPath)
	cmd.Dir = targetDir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: hc_disks.sh failed: %v\nstderr: %s", err, stderr.String())
		return
	}
	data.HCDisks = string(out)
	fmt.Printf(" ✅\n")
}

// runHCUpgradePath checks if hc_upgrade_path.sh exists and is executable, runs it, and stores the output
func runHCUpgradePath(targetDir string, data *models.ArchiveData) {
	scriptPath, err := exec.LookPath("hc_upgrade_path.sh")
	if err != nil {
		return // Not in $PATH, skip silently
	}

	// Prefer n2op.log_all (generated by start_analysis.sh), fall back to n2op.log
	logPath := filepath.Join(targetDir, "data", "log", "n2os", "n2op.log_all")
	if _, err := os.Stat(logPath); err != nil {
		logPath = filepath.Join(targetDir, "data", "log", "n2os", "n2op.log")
		if _, err := os.Stat(logPath); err != nil {
			return // No log file available, skip silently
		}
	}

	fmt.Printf("  Stealing Savario's Upgrade Path analysis...")
	cmd := exec.Command(scriptPath, logPath)
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf(" ❌\n")
		log.Printf("Warning: hc_upgrade_path.sh failed: %v", err)
		return
	}
	data.HCUpgradePath = string(out)
	fmt.Printf(" ✅\n")
}

var knownViews = map[string]bool{
	"dashboard": true,
	"system":    true, "network": true, "storage": true, "database": true,
	"processes": true, "n2os-config": true, "rc-conf": true, "n2op-logs": true,
	"health-events": true, "appliances": true, "logs-all": true, "logs-syslog": true,
	"logs-nginx": true, "logs-auth": true, "n2osjobs-logs": true, "n2osmigrate-logs": true,
	"n2osids": true, "n2osalert": true, "n2osproduction": true,
	"logs-output-analysis": true, "logs-goaccess": true, "logs-post-analysis": true,
	"hc-upgrade-path": true, "hc-disks": true, "issues": true, "overview": true,
}

func runPennyConfig(targetDir string, data *models.ArchiveData) {
	data.LandingView = "system"
	data.Theme = "light"

	cfg, err := pennyconfig.Load()
	if err != nil {
		log.Printf("Warning: penny.yaml failed to load: %v", err)
		return
	}
	if cfg == nil {
		return
	}

	// Run BYOS scripts
	results := pennyconfig.RunAll(cfg, targetDir)
	if len(results) > 0 {
		fmt.Printf("  Running BYOS scripts...\n")
		for _, r := range results {
			if r.Error != "" {
				fmt.Printf("    %-30s ❌ %s\n", r.Name, r.Error)
			} else {
				fmt.Printf("    %-30s ✅\n", r.Name)
			}
			data.ByosResults = append(data.ByosResults, models.ByosResult{
				Name:   r.Name,
				Tag:    r.Tag,
				Output: r.Output,
				Error:  r.Error,
			})
		}
	}

	// Resolve landing view
	landing := cfg.Landing
	if landing != "" {
		if strings.HasPrefix(landing, "byos:") {
			tag := strings.TrimPrefix(landing, "byos:")
			for i, r := range data.ByosResults {
				if r.Tag == tag {
					data.LandingView = fmt.Sprintf("byos-%d", i)
					break
				}
			}
			// tag not found — stays "system" silently
		} else if knownViews[landing] {
			data.LandingView = landing
		} else {
			fmt.Printf("Warning: unknown landing view %q in penny.yaml, defaulting to \"system\"\n", landing)
		}
	}

	// Resolve theme
	switch cfg.Theme {
	case "dark", "light":
		data.Theme = cfg.Theme
	case "":
		// not set, keep default "light"
	default:
		fmt.Printf("Warning: unknown theme %q in penny.yaml, defaulting to \"light\"\n", cfg.Theme)
	}

	// Run known issue scripts from $HOME/.penny or TSE toolkit
	kiRoot, err := pennyconfig.FindKnownIssuesRoot()
	if err != nil {
		return // not found, skip silently
	}
	specs, err := pennyconfig.LoadKnownIssues(kiRoot)
	if err != nil {
		log.Printf("Warning: known_issues.yaml failed to load: %v", err)
		return
	}
	if len(specs) == 0 {
		return
	}

	archiveJSON, err := json.Marshal(data)
	if err != nil {
		log.Printf("Warning: could not marshal archive data for known issues: %v", err)
		return
	}

	fmt.Printf("  Running known issue checks...")
	for _, spec := range specs {
		result, err := pennyconfig.RunKnownIssue(spec, kiRoot, archiveJSON, targetDir, cfg.DebugKI)
		if err != nil {
			continue
		}
		if result == nil {
			continue
		}
		data.KnownIssueResults = append(data.KnownIssueResults, models.KnownIssueResult{
			ID:          result.ID,
			Severity:    result.Severity,
			Title:       result.Title,
			Description: result.Description,
			Workaround:  result.Workaround,
			URL:         result.URL,
		})
	}
	fmt.Printf(" ✅\n")
}

func openBrowser(url string) {
	time.Sleep(1 * time.Second)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "freebsd":
		cmd = exec.Command("xdg-open", url)
	default:
		return
	}
	cmd.Start()
}

func runSetupMode(port int) {
	data := &models.ArchiveData{}
	url := fmt.Sprintf("http://localhost:%d/settings", port)
	fmt.Printf("\nSetup mode — starting server on %s\n", url)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Printf("Opening %s in your browser...\n", url)
	go openBrowser(url)
	if err := server.Start(port, data, version); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func printUsage() {
	fmt.Println("Support Archive Analyzer")
	fmt.Println("Version: " + version)
	fmt.Println("\nUsage:")
	fmt.Println("  Extract and analyze archive or database backup:")
	fmt.Println("    penny -f archive.tbz2 [-o output-dir] [-port 8080]")
	fmt.Println("    penny -f backup.nozomi_backup [-o output-dir] [-port 8080]")
	fmt.Println("\n  Analyze existing directory of the support archive/database backup:")
	fmt.Println("    penny -d directory [-port 8080]")
	fmt.Println("\nFlags:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  penny -f archive.tbz2")
	fmt.Println("  penny -f backup.nozomi_backup")
	fmt.Println("  penny -f archive.tbz2 -o archive")
	fmt.Println("  penny -d ./support/")
	fmt.Println("  penny -d ./support/ -port 9000")
}
