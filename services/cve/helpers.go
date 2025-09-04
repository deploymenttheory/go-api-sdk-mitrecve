package cve

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CVE ID validation regex pattern
var cveIDPattern = regexp.MustCompile(`^CVE-(\d{4})-(\d{4,})$`)

// ValidateCVEID validates if a string is a properly formatted CVE ID
func ValidateCVEID(cveID string) error {
	if cveID == "" {
		return fmt.Errorf("CVE ID cannot be empty")
	}

	matches := cveIDPattern.FindStringSubmatch(cveID)
	if matches == nil {
		return fmt.Errorf("invalid CVE ID format: %s (expected format: CVE-YYYY-NNNNN)", cveID)
	}

	year, err := strconv.Atoi(matches[1])
	if err != nil {
		return fmt.Errorf("invalid year in CVE ID: %s", matches[1])
	}

	if year < MinCVEYear || year > MaxCVEYear {
		return fmt.Errorf("invalid CVE year: %d (must be between %d and %d)", 
			year, MinCVEYear, MaxCVEYear)
	}

	return nil
}

// ExtractYearFromCVEID extracts the year from a CVE ID
func ExtractYearFromCVEID(cveID string) (int, error) {
	if err := ValidateCVEID(cveID); err != nil {
		return 0, err
	}

	matches := cveIDPattern.FindStringSubmatch(cveID)
	year, _ := strconv.Atoi(matches[1]) // We already validated this above
	return year, nil
}

// ExtractSequenceFromCVEID extracts the sequence number from a CVE ID
func ExtractSequenceFromCVEID(cveID string) (int, error) {
	if err := ValidateCVEID(cveID); err != nil {
		return 0, err
	}

	matches := cveIDPattern.FindStringSubmatch(cveID)
	sequence, _ := strconv.Atoi(matches[2]) // We already validated the format above
	return sequence, nil
}

// FormatCVEID formats a CVE ID with proper zero-padding
func FormatCVEID(year, sequence int) string {
	// CVE IDs should have at least 4 digits in the sequence
	if sequence < 10000 {
		return fmt.Sprintf("CVE-%d-%04d", year, sequence)
	}
	return fmt.Sprintf("CVE-%d-%d", year, sequence)
}

// IsValidCVEState checks if the provided state is a valid CVE state
func IsValidCVEState(state CVEState) bool {
	for _, validState := range ValidCVEStates {
		if state == validState {
			return true
		}
	}
	return false
}

// ParseCVEState converts a string to CVEState if valid
func ParseCVEState(stateStr string) (CVEState, error) {
	state := CVEState(strings.ToUpper(stateStr))
	if !IsValidCVEState(state) {
		return "", fmt.Errorf("invalid CVE state: %s (valid states: %v)", 
			stateStr, ValidCVEStates)
	}
	return state, nil
}

// BuildQueryString creates a query string from parameters (for logging)
func (c *Client) buildQueryString(params map[string]string) string {
	var parts []string
	for key, value := range params {
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(parts, "&")
}

// GetCurrentCVEYear returns the current year for CVE purposes
func GetCurrentCVEYear() int {
	return time.Now().Year()
}

// IsRecentCVE checks if a CVE was published within the last N days
func IsRecentCVE(cve *CVERecord, days int) bool {
	if cve.CVEMetadata.DatePublished == nil {
		return false
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	return cve.CVEMetadata.DatePublished.After(cutoff)
}

// HasCVSS checks if a CVE record contains CVSS metrics
func HasCVSS(cve *CVERecord) bool {
	if cve.Containers.CNA != nil {
		for _, metric := range cve.Containers.CNA.Metrics {
			if strings.Contains(strings.ToLower(metric.Format), "cvss") {
				return true
			}
		}
	}

	for _, adp := range cve.Containers.ADP {
		for _, metric := range adp.Metrics {
			if strings.Contains(strings.ToLower(metric.Format), "cvss") {
				return true
			}
		}
	}

	return false
}

// GetPrimaryDescription returns the primary (usually English) description of a CVE
func GetPrimaryDescription(cve *CVERecord) string {
	if cve.Containers.CNA == nil || len(cve.Containers.CNA.Descriptions) == 0 {
		return ""
	}

	// Look for English description first
	for _, desc := range cve.Containers.CNA.Descriptions {
		if desc.Lang == "en" || desc.Lang == "eng" {
			return desc.Value
		}
	}

	// If no English description found, return the first one
	return cve.Containers.CNA.Descriptions[0].Value
}

// GetAffectedProducts returns a list of affected products from a CVE record
func GetAffectedProducts(cve *CVERecord) []string {
	var products []string
	seen := make(map[string]bool)

	if cve.Containers.CNA != nil {
		for _, affected := range cve.Containers.CNA.Affected {
			if affected.Product != "" {
				key := strings.ToLower(affected.Vendor + ":" + affected.Product)
				if !seen[key] {
					if affected.Vendor != "" {
						products = append(products, affected.Vendor+" "+affected.Product)
					} else {
						products = append(products, affected.Product)
					}
					seen[key] = true
				}
			}
		}
	}

	return products
}

// GetReferences returns all references from a CVE record
func GetReferences(cve *CVERecord) []Reference {
	var references []Reference

	if cve.Containers.CNA != nil {
		references = append(references, cve.Containers.CNA.References...)
	}

	for _, adp := range cve.Containers.ADP {
		references = append(references, adp.References...)
	}

	return references
}

// FilterReferencesByTag filters references by specific tags
func FilterReferencesByTag(references []Reference, tag string) []Reference {
	var filtered []Reference

	for _, ref := range references {
		for _, refTag := range ref.Tags {
			if strings.EqualFold(refTag, tag) {
				filtered = append(filtered, ref)
				break
			}
		}
	}

	return filtered
}

// GetCWEIDs extracts CWE IDs from problem types
func GetCWEIDs(cve *CVERecord) []string {
	var cweIds []string
	seen := make(map[string]bool)

	if cve.Containers.CNA != nil {
		for _, problemType := range cve.Containers.CNA.ProblemTypes {
			for _, desc := range problemType.Descriptions {
				if desc.CWEID != "" && !seen[desc.CWEID] {
					cweIds = append(cweIds, desc.CWEID)
					seen[desc.CWEID] = true
				}
			}
		}
	}

	return cweIds
}