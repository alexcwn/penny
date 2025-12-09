# Penny

A powerful support archive analyzer and dashboard for Nozomi Networks N2OS appliances. Penny parses support archives and presents diagnostic information through an intuitive web interface.

## Features

### System Overview
- **System Information**: Hardware specs, version info, uptime, timezone, and asset metrics
- **License Management**: View and analyze license status, expiration dates, and node counts
- **CMC Configuration**: Central Management Console sync settings and proxy configuration

### Log Analysis
- **N2Op Logs**: System operation logs with event type classification (heartbeat, upgrades, service events)
- **Background Tasks**: N2OS job execution logs with duration tracking and JSON inspection
- **Auth Logs**: Authentication events including SSH, sudo, and security events
- **Nginx Logs**: Web server error tracking
- **Health Events**: Categorized health events from appliances and network components

### Upgrade Path Validation
- Automatic validation of upgrade paths against documented requirements
- Detection of invalid upgrade sequences
- Direct links to release documentation
- Support for multi-hop upgrade path analysis

### Network & Storage
- **Network Configuration**: Interface details, IP configuration, routing, and DNS
- **BPF Statistics**: Berkeley Packet Filter stats with delta analysis and issue detection
- **Storage Analysis**: ZFS pool status, disk health (SMART), and disk usage visualization
- **Database Diagnostics**: PostgreSQL table sizes, vacuum status, and health metrics

### Configuration Analysis
- **N2OS Config**: Searchable configuration viewer with masking for sensitive data
- **RC Configuration**: FreeBSD rc.conf settings viewer

### Advanced Features
- **Search & Filter**: Boolean operators (AND `&`, OR `|`, NOT `!`) across logs and configs
- **Pagination**: Efficient handling of large log files (30k+ entries)
- **Dark Mode**: Built-in dark theme support
- **Click-to-Expand**: Long log lines with fade-out indicators and expandable views
- **JSON Viewer**: Modal viewer for JSON-formatted log entries
- **Toggle Columns**: Show/hide optional columns (source, line numbers) with localStorage persistence

## Installation

### Prerequisites
- Go 1.19 or higher
- A Nozomi Networks support archive (`.tgz` file)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/penny.git
cd penny

# Build the binary
go build -o penny cmd/penny/main.go

# Or use the provided build script
./build.sh
```

## Usage

### Basic Usage

```bash
# Extract and analyze a support archive
penny -d /path/to/extracted/support/archive

# Specify a custom port (default: 8080)
penny -d /path/to/support/archive -port 9000
```

### Command-Line Options

```
-d string
    Path to extracted support archive directory (required)
-port int
    HTTP server port (default: 8080)
```

### Example

```bash
# Extract your support archive
tar -xzf support-archive-2025-01-27.tgz

# Run Penny
penny -d ./support-archive-2025-01-27

# Open your browser to http://localhost:8080
```

## Architecture

### Backend (Go)
- **Parser Package**: Modular parsers for different log formats and config files
- **Models Package**: Structured data types for all parsed information
- **Validator Package**: Upgrade path validation engine with YAML rule definitions
- **Server Package**: HTTP server with embedded static files and JSON API endpoints

### Frontend (Vanilla JavaScript)
- Single-page application with no external dependencies
- Responsive design with CSS Grid and Flexbox
- Client-side search, filtering, and pagination
- LocalStorage for user preferences

### API Endpoints
- `/api/metadata` - Archive metadata
- `/api/system` - System information and licenses
- `/api/logs` - Syslog messages
- `/api/processes` - Process list
- `/api/network` - Network configuration
- `/api/bpf-stats` - BPF statistics
- `/api/storage` - Storage and ZFS info
- `/api/overview` - High-level overview
- `/api/issues` - Detected issues
- `/api/n2os-config` - N2OS configuration
- `/api/n2op-logs` - Operation logs with upgrade violations
- `/api/n2osjobs-logs` - Background task logs
- `/api/health-events` - Health event logs
- `/api/database` - Database diagnostics

## Development

### Project Structure

```
penny/
├── cmd/penny/           # Application entry point
├── internal/
│   ├── models/         # Data structures
│   ├── parser/         # Log and config parsers
│   ├── server/         # HTTP server
│   │   └── static/     # Embedded web UI
│   └── validator/      # Upgrade validation logic
│       └── upgrade_rules.yaml
├── README.md
└── go.mod
```

### Adding New Parsers

1. Define your data structure in `internal/models/models.go`
2. Create a parser function in `internal/parser/`
3. Call your parser in `internal/parser/parser.go`
4. Add an API endpoint in `internal/server/handlers.go`
5. Update the frontend to display the new data

### Extending Upgrade Validation

Edit `internal/validator/upgrade_rules.yaml` to add new version rules:

```yaml
valid_upgrades:
  "25.6.0":
    - "25.5.0"
    - "25.4.0"

recommended_paths:
  "24.0.0->25.6.0": ["24.6.0", "25.0.0"]

docs_urls:
  "25.6.0": "https://technicaldocs.nozominetworks.com/..."
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style
- Follow Go standard formatting (`gofmt`)
- Write clear commit messages
- Add comments for complex logic
- Update documentation as needed

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for Nozomi Networks N2OS support archive analysis
- Inspired by the need for faster support archive diagnostics
- Uses embedded static files for zero-dependency deployment

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Check existing issues for similar problems
- Provide support archive details (redacted) when reporting bugs

## Roadmap

- [ ] Export functionality (PDF/HTML reports)
- [ ] Comparative analysis (multiple archives)
- [ ] Real-time log tailing
- [ ] Plugin system for custom parsers
- [ ] Docker containerization
- [ ] CI/CD pipeline integration

---

**Note**: This tool is designed for analyzing Nozomi Networks N2OS support archives. It is not affiliated with or officially supported by Nozomi Networks.
