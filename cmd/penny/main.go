package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"penny/internal/extractor"
	"penny/internal/models"
	"penny/internal/parser"
	"penny/internal/server"
	"strings"
)

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
	archiveFile := flag.String("f", "", "Archive file path (.tbz2)")
	outputDir := flag.String("o", "", "Output directory for extraction")
	analyzeDir := flag.String("d", "", "Directory to analyze (existing extraction)")
	port := flag.Int("port", 8080, "HTTP server port")

	flag.Parse()

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
		if !isPosixTarArchive(*archiveFile) {
			log.Fatal("Error: Not a valid Support Archive compressed file.")
		}

		// Determine output directory
		if *outputDir == "" {
			targetDir = promptForDirectory()
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
	} else {
		// Analyze existing directory mode
		targetDir = *analyzeDir

		// Check if directory exists
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			log.Fatalf("Error: Directory '%s' does not exist", targetDir)
		}
	}

	// Parse the archive data
	fmt.Printf("Parsing data from %s...\n", targetDir)
	data, err := parseArchive(targetDir)
	if err != nil {
		log.Fatalf("Error parsing archive: %v", err)
	}
	fmt.Printf("Parsing complete. Found %d log entries.\n",
		len(data.Logs.Messages)+len(data.Logs.NginxErrors))

	// Start web server
	fmt.Printf("\nStarting server on http://localhost:%d\n", *port)
	fmt.Println("Press Ctrl+C to stop")

	if err := server.Start(*port, data); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

// isPosixTarArchive checks if the file is a POSIX TAR archive by examining its magic numbers
func isPosixTarArchive(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Warning: Could not open file for magic number check: %v", err)
		return false
	}
	defer file.Close()

	// Read the first 512 bytes to check for TAR signatures
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		log.Printf("Warning: Could not read file for magic number check: %v", err)
		return false
	}

	// Check for POSIX TAR archive magic numbers
	for _, magic := range magicNumbers {
		if magic.Type == "POSIX TAR archive" {
			// Check if we have enough bytes to read the signature
			if magic.Offset+len(magic.Bytes) <= n {
				// Compare the bytes at the specified offset
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

func promptForDirectory() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Extract to directory [default: support]: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return "support"
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
	if err := parser.ParseSystemInfo(dir, data); err != nil {
		log.Printf("Warning: Error parsing system info: %v", err)
	}

	// Parse logs
	if err := parser.ParseLogs(dir, data); err != nil {
		log.Printf("Warning: Error parsing logs: %v", err)
	}

	// Parse process list
	if err := parser.ParseProcessList(dir, data); err != nil {
		log.Printf("Warning: Error parsing process list: %v", err)
	}

	// Parse network config
	if err := parser.ParseNetworkConfig(dir, data); err != nil {
		log.Printf("Warning: Error parsing network config: %v", err)
	}

	// Parse BPF statistics
	if err := parser.ParseBPFStats(dir, data); err != nil {
		log.Printf("Warning: Error parsing BPF stats: %v", err)
	}

	// Parse storage info
	if err := parser.ParseStorage(dir, data); err != nil {
		log.Printf("Warning: Error parsing storage info: %v", err)
	}

	// Parse N2OS config
	if err := parser.ParseN2OSConfig(dir, data); err != nil {
		log.Printf("Warning: Error parsing N2OS config: %v", err)
	}

	return data, nil
}

func printUsage() {
	fmt.Println("Support Archive Analyzer")
	fmt.Println("\nUsage:")
	fmt.Println("  Extract and analyze archive:")
	fmt.Println("    penny -f archive.tbz2 [-o output-dir] [-port 8080]")
	fmt.Println("\n  Analyze existing directory:")
	fmt.Println("    penny -d directory [-port 8080]")
	fmt.Println("\nFlags:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  penny -f archive.tbz2")
	fmt.Println("  penny -f archive.tbz2 -o my-analysis")
	fmt.Println("  penny -d ./support/")
	fmt.Println("  penny -d ./support/ -port 9000")
}
