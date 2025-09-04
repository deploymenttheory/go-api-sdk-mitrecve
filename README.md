# Go API SDK for MITRE CVE Services

[![Go Reference](https://pkg.go.dev/badge/github.com/deploymenttheory/go-api-sdk-mitrecve.svg)](https://pkg.go.dev/github.com/deploymenttheory/go-api-sdk-mitrecve)
[![Go Report Card](https://goreportcard.com/badge/github.com/deploymenttheory/go-api-sdk-mitrecve)](https://goreportcard.com/report/github.com/deploymenttheory/go-api-sdk-mitrecve)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive Go SDK for interacting with the [MITRE CVE Services API](https://cveawg.mitre.org/api-docs/). This SDK provides a clean, idiomatic Go interface for searching, retrieving, and managing CVE (Common Vulnerabilities and Exposures) records.

## Features

- **🔍 CVE Search & Retrieval**: Search for CVEs by year, state, organization, and other criteria
- **📋 CVE Record Management**: Retrieve detailed CVE records with full metadata
- **🏢 Organization Management**: Manage users and organization settings (requires authentication)
- **🔐 Authentication Support**: Full support for API key authentication
- **✅ Input Validation**: Comprehensive validation of CVE IDs and parameters  
- **📊 Rich Data Models**: Complete Go structs mapping the CVE 5.1 JSON schema
- **🛠 Helper Functions**: Utility functions for CVE ID parsing, validation, and data extraction
- **📝 Comprehensive Examples**: Ready-to-use examples for common use cases
- **🧪 Well Tested**: Extensive unit tests ensuring reliability

## Installation

```bash
go get github.com/deploymenttheory/go-api-sdk-mitrecve
```

## Quick Start

### Basic CVE Search (No Authentication Required)

```go
package main

import (
    "fmt"
    "log"

    "github.com/deploymenttheory/go-api-sdk-mitrecve/services/cve"
)

func main() {
    // Create a new CVE client
    client := cve.NewDefaultClient()

    // Search for published CVEs from 2023
    params := cve.NewSearchParams().
        Year(2023).
        State(cve.CVEStatePublished).
        Limit(10).
        Build()

    response, err := client.SearchCVEs(params)
    if err != nil {
        log.Fatalf("Error searching CVEs: %v", err)
    }

    fmt.Printf("Found %d CVEs from 2023\n", response.TotalCount)
    for _, cveID := range response.CVEIds {
        fmt.Printf("  - %s\n", cveID)
    }
}
```

### Retrieve CVE Details

```go
// Get detailed information for a specific CVE
cveRecord, err := client.GetCVERecord("CVE-2023-12345")
if err != nil {
    log.Fatalf("Error getting CVE record: %v", err)
}

fmt.Printf("CVE: %s\n", cveRecord.CVEMetadata.CVEID)
fmt.Printf("State: %s\n", cveRecord.CVEMetadata.State)
fmt.Printf("Description: %s\n", cve.GetPrimaryDescription(cveRecord))

// Get affected products
products := cve.GetAffectedProducts(cveRecord)
for _, product := range products {
    fmt.Printf("Affected: %s\n", product)
}
```

### Authenticated Operations

For operations requiring authentication (CVE ID reservation, user management), you'll need API credentials:

```go
package main

import (
    "github.com/deploymenttheory/go-api-sdk-mitrecve/services/cve"
    "github.com/deploymenttheory/go-api-sdk-mitrecve/services/organization"
)

func main() {
    // Create authenticated clients
    cveClient := cve.NewClientWithAuth("your-api-key", "your-secret-key")
    orgClient := organization.NewClientWithAuth("your-api-key", "your-secret-key")

    // Reserve CVE IDs (requires CNA privileges)
    reservation := cve.CVEIDReservationRequest{
        CVEYear:    2024,
        CVEIDCount: 5,
        ShortName:  "your-org",
    }
    
    result, err := cveClient.ReserveCVEIDs(reservation)
    if err != nil {
        log.Fatalf("Error reserving CVE IDs: %v", err)
    }
    
    fmt.Printf("Reserved CVE IDs: %v\n", result.CVEIds)
}
```

## Configuration

### Basic Configuration

```go
import "github.com/deploymenttheory/go-api-sdk-mitrecve/client"

config := client.Config{
    BaseURL:    "https://cveawg.mitre.org/api", // Default
    Timeout:    30 * time.Second,               // Default
    RetryCount: 3,                              // Default
    RetryDelay: 1 * time.Second,                // Default
    UserAgent:  "my-app/1.0.0",
    Debug:      true,                           // Enable debug logging
}

baseClient := client.NewClient(config)
cveClient := cve.NewClient(baseClient)
```

### Environment Variables

For authenticated operations, you can use environment variables:

```bash
export CVE_API_KEY="your-api-key"
export CVE_SECRET_KEY="your-secret-key"
```

## API Coverage

### CVE Operations

- ✅ **Search CVEs**: Search by year, state, organization, time modified
- ✅ **Get CVE Record**: Retrieve complete CVE record by ID
- ✅ **Reserve CVE IDs**: Reserve new CVE IDs (requires CNA privileges)
- ✅ **Validate CVE IDs**: Client-side validation of CVE ID format

### Organization Operations  

- ✅ **Get Organization**: Retrieve organization details
- ✅ **List Users**: List users in organization
- ✅ **Get User**: Get specific user details
- ✅ **Create User**: Create new user accounts
- ✅ **Update User**: Update existing user information

### Helper Functions

- ✅ **CVE ID Validation**: `ValidateCVEID()`, `ExtractYearFromCVEID()`, `ExtractSequenceFromCVEID()`
- ✅ **Data Extraction**: `GetPrimaryDescription()`, `GetAffectedProducts()`, `GetCWEIDs()`, `GetReferences()`
- ✅ **Filtering**: `FilterReferencesByTag()`, `IsRecentCVE()`, `HasCVSS()`
- ✅ **State Management**: `IsValidCVEState()`, `ParseCVEState()`

## Examples

The `examples/` directory contains complete working examples:

- **[basic_search.go](examples/basic_search.go)**: Basic CVE searching and data extraction
- **[authenticated_operations.go](examples/authenticated_operations.go)**: CVE ID reservation and user management

Run the examples:

```bash
# Basic search (no authentication required)
go run examples/basic_search.go

# Authenticated operations (requires API credentials)
CVE_API_KEY="your-key" CVE_SECRET_KEY="your-secret" go run examples/authenticated_operations.go
```

## Testing

The SDK includes comprehensive unit tests:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific service tests
go test ./services/cve/
go test ./services/organization/
```

## Data Models

The SDK provides complete Go structs for all CVE API data:

```go
type CVERecord struct {
    DataType    string      `json:"dataType"`
    DataVersion string      `json:"dataVersion"`
    CVEMetadata CVEMetadata `json:"cveMetadata"`
    Containers  Containers  `json:"containers"`
}

type CVEMetadata struct {
    CVEID             string     `json:"cveId"`
    AssignerOrgID     string     `json:"assignerOrgId"`
    State             CVEState   `json:"state"`
    DatePublished     *time.Time `json:"datePublished,omitempty"`
    DateReserved      *time.Time `json:"dateReserved,omitempty"`
    // ... additional fields
}
```

## Error Handling

The SDK provides structured error handling with detailed error messages:

```go
cveRecord, err := client.GetCVERecord("invalid-cve-id")
if err != nil {
    // Errors include context about what failed and why
    fmt.Printf("Error: %v\n", err)
}

// Validate CVE IDs before making API calls
if err := cve.ValidateCVEID("CVE-2023-1234"); err != nil {
    fmt.Printf("Invalid CVE ID: %v\n", err)
}
```

## Logging

The SDK uses structured logging with [zap](https://github.com/uber-go/zap):

```go
config := client.Config{
    Debug: true, // Enable debug logging
}
client := client.NewClient(config)

// Debug mode provides detailed request/response logging
```

## Rate Limiting & Retries

The SDK includes built-in retry logic with exponential backoff:

```go
config := client.Config{
    RetryCount: 3,                    // Number of retries
    RetryDelay: 1 * time.Second,      // Initial delay
    Timeout:    30 * time.Second,     // Request timeout
}
```

## CVE States

The SDK supports all official CVE states:

```go
// Available CVE states
cve.CVEStateReserved   // "RESERVED"
cve.CVEStatePublished  // "PUBLISHED" 
cve.CVEStateRejected   // "REJECTED"

// Search by state
params := cve.NewSearchParams().
    State(cve.CVEStatePublished).
    Build()
```

## Requirements

- Go 1.21 or later
- Network access to `cveawg.mitre.org`
- API credentials for authenticated operations (CVE ID reservation, user management)

## Authentication

To use authenticated features:

1. Register for API access at [MITRE CVE Services](https://cveawg.mitre.org/)
2. Obtain your API key and secret key
3. Use `NewClientWithAuth()` or set credentials via environment variables

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/deploymenttheory/go-api-sdk-mitrecve.git
cd go-api-sdk-mitrecve

# Install dependencies
go mod download

# Run tests
go test ./...

# Run examples
go run examples/basic_search.go
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [MITRE CVE Services API Documentation](https://cveawg.mitre.org/api-docs/)
- [CVE JSON Schema](https://github.com/CVEProject/cve-schema)
- [go-api-sdk-apple](https://github.com/deploymenttheory/go-api-sdk-apple) - Similar SDK pattern for Apple APIs

## Support

- 📧 **Issues**: [GitHub Issues](https://github.com/deploymenttheory/go-api-sdk-mitrecve/issues)
- 📖 **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/deploymenttheory/go-api-sdk-mitrecve)
- 🌐 **MITRE CVE Services**: [Official API Docs](https://cveawg.mitre.org/api-docs/)

---

*This SDK is not officially affiliated with MITRE Corporation. CVE is a trademark of MITRE Corporation.*
