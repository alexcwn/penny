package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"penny/internal/extractor"
	"penny/internal/models"
	"penny/internal/parser"
	"penny/internal/server"
)

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
