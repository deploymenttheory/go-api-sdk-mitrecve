package main

import (
	"fmt"
	"log"

	"github.com/deploymenttheory/go-api-sdk-mitrecve/services/cve"
)

func main() {
	// Create a new CVE client
	client := cve.NewDefaultClient()
	defer client.Close()

	// Example 1: Search for CVEs from 2023
	fmt.Println("=== Example 1: Search CVEs from 2023 ===")
	params := cve.NewSearchParams().
		Year(2023).
		State(cve.CVEStatePublished).
		Limit(5).
		Build()

	response, err := client.SearchCVEs(params)
	if err != nil {
		log.Fatalf("Error searching CVEs: %v", err)
	}

	fmt.Printf("Found %d CVEs from 2023\n", response.TotalCount)
	fmt.Printf("Showing first %d results:\n", len(response.CVEIds))
	for _, cveID := range response.CVEIds {
		fmt.Printf("  - %s\n", cveID)
	}

	// Example 2: Get details for a specific CVE
	if len(response.CVEIds) > 0 {
		fmt.Printf("\n=== Example 2: Get CVE Details for %s ===\n", response.CVEIds[0])
		
		cveRecord, err := client.GetCVERecord(response.CVEIds[0])
		if err != nil {
			log.Printf("Error getting CVE record: %v", err)
		} else {
			fmt.Printf("CVE ID: %s\n", cveRecord.CVEMetadata.CVEID)
			fmt.Printf("State: %s\n", cveRecord.CVEMetadata.State)
			fmt.Printf("Assigner: %s\n", cveRecord.CVEMetadata.AssignerShortName)
			
			if cveRecord.CVEMetadata.DatePublished != nil {
				fmt.Printf("Published: %s\n", cveRecord.CVEMetadata.DatePublished.Format("2006-01-02"))
			}
			
			// Get primary description
			description := cve.GetPrimaryDescription(cveRecord)
			if description != "" {
				fmt.Printf("Description: %.200s...\n", description)
			}
			
			// Get affected products
			products := cve.GetAffectedProducts(cveRecord)
			if len(products) > 0 {
				fmt.Printf("Affected Products:\n")
				for _, product := range products {
					fmt.Printf("  - %s\n", product)
				}
			}
			
			// Get CWE IDs
			cweIds := cve.GetCWEIDs(cveRecord)
			if len(cweIds) > 0 {
				fmt.Printf("CWE IDs: %v\n", cweIds)
			}
		}
	}

	// Example 3: Search for recent CVEs with specific state
	fmt.Println("\n=== Example 3: Search Recent Reserved CVEs ===")
	recentParams := cve.NewSearchParams().
		State(cve.CVEStateReserved).
		Year(cve.GetCurrentCVEYear()).
		Limit(3).
		Build()

	recentResponse, err := client.SearchCVEs(recentParams)
	if err != nil {
		log.Printf("Error searching recent CVEs: %v", err)
	} else {
		fmt.Printf("Found %d reserved CVEs from %d\n", 
			recentResponse.TotalCount, cve.GetCurrentCVEYear())
		for i, cveID := range recentResponse.CVEIds {
			if i >= 3 { // Limit to first 3
				break
			}
			fmt.Printf("  - %s\n", cveID)
		}
	}

	// Example 4: Validate CVE ID format
	fmt.Println("\n=== Example 4: CVE ID Validation ===")
	testCVEs := []string{
		"CVE-2023-1234",
		"CVE-2023-12345",
		"CVE-invalid-format",
		"CVE-1998-1234", // Too old
		"CVE-2025-0001",
	}

	for _, testCVE := range testCVEs {
		if err := cve.ValidateCVEID(testCVE); err != nil {
			fmt.Printf("  ❌ %s: %v\n", testCVE, err)
		} else {
			year, _ := cve.ExtractYearFromCVEID(testCVE)
			sequence, _ := cve.ExtractSequenceFromCVEID(testCVE)
			fmt.Printf("  ✅ %s: Year=%d, Sequence=%d\n", testCVE, year, sequence)
		}
	}
}