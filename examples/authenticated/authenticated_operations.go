package main

import (
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-mitrecve/services/cve"
	"github.com/deploymenttheory/go-api-sdk-mitrecve/services/organization"
)

func main() {
	// Get credentials from environment variables
	apiKey := os.Getenv("CVE_API_KEY")
	secretKey := os.Getenv("CVE_SECRET_KEY")

	if apiKey == "" || secretKey == "" {
		log.Println("This example requires CVE_API_KEY and CVE_SECRET_KEY environment variables")
		log.Println("Skipping authenticated operations...")
		return
	}

	// Create authenticated clients
	cveClient := cve.NewClientWithAuth(apiKey, secretKey)
	defer cveClient.Close()

	orgClient := organization.NewClientWithAuth(apiKey, secretKey)
	defer orgClient.Close()

	// Example 1: Reserve CVE IDs (requires CNA privileges)
	fmt.Println("=== Example 1: Reserve CVE IDs ===")
	reservationRequest := cve.CVEIDReservationRequest{
		CVEYear:    cve.GetCurrentCVEYear(),
		CVEIDCount: 2,
		ShortName:  "example-org",
	}

	reservation, err := cveClient.ReserveCVEIDs(reservationRequest)
	if err != nil {
		log.Printf("Error reserving CVE IDs (this requires CNA privileges): %v", err)
	} else {
		fmt.Printf("Successfully reserved %d CVE IDs:\n", len(reservation.CVEIds))
		for _, cveID := range reservation.CVEIds {
			fmt.Printf("  - %s\n", cveID)
		}
		fmt.Printf("Reservation time: %s\n", reservation.TimeReserved.Format("2006-01-02 15:04:05"))
	}

	// Example 2: List organization users
	fmt.Println("\n=== Example 2: List Organization Users ===")
	users, err := orgClient.ListUsers(10, 0)
	if err != nil {
		log.Printf("Error listing users: %v", err)
	} else {
		fmt.Printf("Found %d users in organization:\n", users.TotalCount)
		for _, user := range users.Users {
			fmt.Printf("  - %s (%s) - Roles: %v\n", 
				user.Username, user.Email, user.Roles)
		}
	}

	// Example 3: Get organization details
	fmt.Println("\n=== Example 3: Get Organization Details ===")
	// Note: You would need to know your organization ID for this to work
	// This is just an example of how you would call it
	orgID := "example-org-id"
	org, err := orgClient.GetOrganization(orgID)
	if err != nil {
		log.Printf("Error getting organization details: %v", err)
	} else {
		fmt.Printf("Organization: %s (%s)\n", org.Name, org.ShortName)
		fmt.Printf("CNA Status: %v\n", org.IsCNA)
		fmt.Printf("CVE ID Quota: %d/%d used\n", org.CVEIDUsed, org.CVEIDQuota)
		fmt.Printf("Website: %s\n", org.Website)
	}

	fmt.Println("\n=== Authenticated Operations Complete ===")
	fmt.Println("Note: Some operations may fail if your account doesn't have the required privileges")
}