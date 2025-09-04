# Scripts

This directory contains utility scripts for the go-api-sdk-mitrecve project.

## fetch-cve-data.go

A native Go script that retrieves CVE data from multiple sources using HTTP method-based naming patterns and organizes it into the repository. Uses only Go libraries without external tool dependencies.

### Purpose
Gets CVE data from:
- MITRE CVE Project (via GitHub API using go-github v74)
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities) Catalog
- CVEDetails
- Tenable

### Usage
```bash
# Run from the repository root
go run scripts/fetch-cve-data.go
```

### Requirements
- Go 1.23 or later
- Internet connection
- **No external tools required** - all operations are native Go
- Dependencies (automatically managed via go.mod):
  - go-github v74 (GitHub API client)
  - Resty HTTP client
  - Zap structured logger

### Features
- **Native Go Operations**: No external tool dependencies (git, curl, etc.)
- **Error Handling**: Continues retrieving from other sources even if one fails
- **Structured Logging**: Uses Zap logger with color-coded output and structured fields
- **GitHub API Integration**: Uses go-github v74 for repository operations
- **Directory Management**: Creates organized directory structure for different data sources
- **Update Tracking**: Records last update timestamps for each source
- **Decompression**: Handles gzip-compressed files automatically
- **HTTP Client**: Uses Resty HTTP client with retry logic and timeouts
- **Resilient Downloads**: Automatic retries with exponential backoff for failed requests
- **Color-Coded Logs**: Info (green), Warn (yellow), Error (red) log levels with timestamps
- **Data Summary**: Creates detailed summary of retrieved data

### Directory Structure
After running, the script creates the following structure:
```
cve-data/
├── mitre/              # MITRE CVE data (via GitHub API archive)
├── nvd/                # NVD JSON data files
├── cisa-kev/           # CISA KEV catalog
├── cvedetails/         # CVEDetails recent CVEs
├── tenable/            # Tenable CVE data
└── retrieval-summary.txt # Summary of retrieval operation
```

Each directory contains a `last-updated.txt` file with the timestamp of the last successful update.

### Error Handling
- Pure Go implementation - no external tool validation needed
- Graceful handling of network failures via GitHub API and HTTP retries
- Continues with remaining sources if one fails
- Detailed structured error messages for troubleshooting
- Uses go-github v74 for reliable GitHub API operations
