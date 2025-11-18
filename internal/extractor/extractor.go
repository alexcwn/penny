package extractor

import (
	"archive/tar"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extract extracts a tar archive (with optional compression) to the specified directory
func Extract(archivePath, targetDir string) error {
	// Open the archive file
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	// Detect compression type and create appropriate reader
	reader, err := getReader(file)
	if err != nil {
		return fmt.Errorf("failed to detect compression: %w", err)
	}

	// Create tar reader
	tarReader := tar.NewReader(reader)

	// Create target directory
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip . directory entry
		if header.Name == "." || header.Name == "./" {
			continue
		}

		// Sanitize file path to prevent directory traversal
		target := filepath.Join(targetDir, header.Name)
		cleanTarget := filepath.Clean(target)
		cleanTargetDir := filepath.Clean(targetDir)

		// Ensure the target is within the target directory
		if !strings.HasPrefix(cleanTarget, cleanTargetDir) {
			return fmt.Errorf("illegal file path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", target, err)
			}

		case tar.TypeReg:
			// Create parent directories if needed
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", target, err)
			}

			// Create file
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", target, err)
			}

			// Copy file contents
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", target, err)
			}

			outFile.Close()

			// Set file permissions
			if err := os.Chmod(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set permissions for %s: %w", target, err)
			}

		case tar.TypeSymlink:
			// Create symlink
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink %s: %w", target, err)
			}

		default:
			// Skip other types (block devices, char devices, etc.)
			continue
		}
	}

	return nil
}

// getReader detects compression type and returns appropriate reader
func getReader(file *os.File) (io.Reader, error) {
	// Read first few bytes to detect file type
	header := make([]byte, 3)
	if _, err := file.Read(header); err != nil {
		return nil, err
	}

	// Seek back to beginning
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	// Check for bzip2 magic bytes (BZ)
	if header[0] == 0x42 && header[1] == 0x5a {
		return bzip2.NewReader(file), nil
	}

	// Check for gzip magic bytes
	if header[0] == 0x1f && header[1] == 0x8b {
		return gzip.NewReader(file)
	}

	// Assume uncompressed tar
	return file, nil
}
