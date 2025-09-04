package cve

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// SearchParamsBuilder helps build search parameters for CVE queries
type SearchParamsBuilder struct {
	params map[string]string
}

// NewSearchParams creates a new search parameters builder
func NewSearchParams() *SearchParamsBuilder {
	return &SearchParamsBuilder{
		params: make(map[string]string),
	}
}

// CVEID filters by specific CVE ID
func (sp *SearchParamsBuilder) CVEID(cveID string) *SearchParamsBuilder {
	if cveID != "" {
		sp.params[ParamCVEID] = cveID
	}
	return sp
}

// State filters by CVE state (RESERVED, PUBLISHED, REJECTED)
func (sp *SearchParamsBuilder) State(state CVEState) *SearchParamsBuilder {
	if state != "" {
		sp.params[ParamState] = string(state)
	}
	return sp
}

// AssignerOrgID filters by assigner organization ID
func (sp *SearchParamsBuilder) AssignerOrgID(orgID string) *SearchParamsBuilder {
	if orgID != "" {
		sp.params[ParamAssignerOrgID] = orgID
	}
	return sp
}

// Year filters by CVE ID year
func (sp *SearchParamsBuilder) Year(year int) *SearchParamsBuilder {
	if year >= MinCVEYear && year <= MaxCVEYear {
		sp.params[ParamYear] = strconv.Itoa(year)
	}
	return sp
}

// TimeModifiedBefore filters by CVEs modified before the specified time
func (sp *SearchParamsBuilder) TimeModifiedBefore(before time.Time) *SearchParamsBuilder {
	sp.params[ParamTimeModified] = before.Format(time.RFC3339)
	return sp
}

// Limit sets the maximum number of results to return
func (sp *SearchParamsBuilder) Limit(limit int) *SearchParamsBuilder {
	if limit > 0 {
		if limit > MaxLimit {
			limit = MaxLimit
		}
		sp.params[ParamLimit] = strconv.Itoa(limit)
	}
	return sp
}

// Offset sets the number of results to skip
func (sp *SearchParamsBuilder) Offset(offset int) *SearchParamsBuilder {
	if offset >= 0 {
		sp.params[ParamOffset] = strconv.Itoa(offset)
	}
	return sp
}

// CountOnly returns only the count of matching results
func (sp *SearchParamsBuilder) CountOnly(countOnly bool) *SearchParamsBuilder {
	if countOnly {
		sp.params[ParamCountOnly] = "true"
	}
	return sp
}

// Build returns the constructed parameters map
func (sp *SearchParamsBuilder) Build() map[string]string {
	// Set defaults if not specified
	if _, exists := sp.params[ParamLimit]; !exists {
		sp.params[ParamLimit] = strconv.Itoa(DefaultLimit)
	}
	if _, exists := sp.params[ParamOffset]; !exists {
		sp.params[ParamOffset] = strconv.Itoa(DefaultOffset)
	}
	
	return sp.params
}

// SearchCVEs searches for CVE IDs based on the provided parameters
func (c *Client) SearchCVEs(params map[string]string) (*CVEListResponse, error) {
	c.logger.Debug("Searching CVEs", zap.Any("params", params))

	resp, err := c.baseClient.HTTP.R().
		SetQueryParams(params).
		Get(CVEIDEndpoint)

	if err != nil {
		c.logger.Error("Failed to search CVEs", zap.Error(err))
		return nil, fmt.Errorf("failed to search CVEs: %w", err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("CVE search request failed", 
			zap.Int("status", resp.StatusCode()),
			zap.String("body", string(resp.Body())))
		
		// Try to parse error response
		var errorResp ErrorResponse
		if err := json.Unmarshal(resp.Body(), &errorResp); err == nil {
			return nil, fmt.Errorf("CVE search failed (status %d): %s - %s", 
				resp.StatusCode(), errorResp.Error, errorResp.Message)
		}
		
		return nil, fmt.Errorf("CVE search failed with status %d", resp.StatusCode())
	}

	var searchResponse CVEListResponse
	err = json.Unmarshal(resp.Body(), &searchResponse)
	if err != nil {
		c.logger.Error("Failed to unmarshal CVE search response", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal CVE search response: %w", err)
	}

	c.logger.Debug("CVE search successful",
		zap.Int("totalCount", searchResponse.TotalCount),
		zap.Int("itemsPerPage", searchResponse.ItemsPerPage),
		zap.Int("currentPage", searchResponse.CurrentPage))

	return &searchResponse, nil
}

// GetCVERecord retrieves a specific CVE record by ID
func (c *Client) GetCVERecord(cveID string) (*CVERecord, error) {
	if cveID == "" {
		return nil, fmt.Errorf("CVE ID is required")
	}

	c.logger.Debug("Retrieving CVE record", zap.String("cve_id", cveID))

	resp, err := c.baseClient.HTTP.R().
		Get(fmt.Sprintf("%s/%s", CVERecordEndpoint, cveID))

	if err != nil {
		c.logger.Error("Failed to get CVE record", zap.Error(err), zap.String("cve_id", cveID))
		return nil, fmt.Errorf("failed to get CVE record %s: %w", cveID, err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("CVE record request failed", 
			zap.String("cve_id", cveID),
			zap.Int("status", resp.StatusCode()),
			zap.String("body", string(resp.Body())))
		
		// Try to parse error response
		var errorResp ErrorResponse
		if err := json.Unmarshal(resp.Body(), &errorResp); err == nil {
			return nil, fmt.Errorf("failed to get CVE record %s (status %d): %s - %s", 
				cveID, resp.StatusCode(), errorResp.Error, errorResp.Message)
		}
		
		return nil, fmt.Errorf("failed to get CVE record %s with status %d", cveID, resp.StatusCode())
	}

	var cveRecord CVERecord
	err = json.Unmarshal(resp.Body(), &cveRecord)
	if err != nil {
		c.logger.Error("Failed to unmarshal CVE record", zap.Error(err), zap.String("cve_id", cveID))
		return nil, fmt.Errorf("failed to unmarshal CVE record %s: %w", cveID, err)
	}

	c.logger.Debug("CVE record retrieved successfully", 
		zap.String("cve_id", cveID),
		zap.String("state", string(cveRecord.CVEMetadata.State)))

	return &cveRecord, nil
}

// ReserveCVEIDs reserves one or more CVE IDs for a given year
func (c *Client) ReserveCVEIDs(request CVEIDReservationRequest) (*CVEIDReservationResponse, error) {
	if request.CVEYear < MinCVEYear || request.CVEYear > MaxCVEYear {
		return nil, fmt.Errorf("invalid CVE year: %d (must be between %d and %d)", 
			request.CVEYear, MinCVEYear, MaxCVEYear)
	}

	if request.CVEIDCount <= 0 {
		return nil, fmt.Errorf("CVE ID count must be greater than 0")
	}

	c.logger.Debug("Reserving CVE IDs", 
		zap.Int("year", request.CVEYear),
		zap.Int("count", request.CVEIDCount),
		zap.String("shortName", request.ShortName))

	resp, err := c.baseClient.HTTP.R().
		SetBody(request).
		Post(CVEIDEndpoint)

	if err != nil {
		c.logger.Error("Failed to reserve CVE IDs", zap.Error(err))
		return nil, fmt.Errorf("failed to reserve CVE IDs: %w", err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("CVE ID reservation failed", 
			zap.Int("status", resp.StatusCode()),
			zap.String("body", string(resp.Body())))
		
		// Try to parse error response
		var errorResp ErrorResponse
		if err := json.Unmarshal(resp.Body(), &errorResp); err == nil {
			return nil, fmt.Errorf("CVE ID reservation failed (status %d): %s - %s", 
				resp.StatusCode(), errorResp.Error, errorResp.Message)
		}
		
		return nil, fmt.Errorf("CVE ID reservation failed with status %d", resp.StatusCode())
	}

	var reservationResponse CVEIDReservationResponse
	err = json.Unmarshal(resp.Body(), &reservationResponse)
	if err != nil {
		c.logger.Error("Failed to unmarshal CVE ID reservation response", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal CVE ID reservation response: %w", err)
	}

	c.logger.Debug("CVE IDs reserved successfully", 
		zap.Int("count", len(reservationResponse.CVEIds)),
		zap.Strings("cve_ids", reservationResponse.CVEIds))

	return &reservationResponse, nil
}