package cve

// API endpoints
const (
	// CVE ID endpoints
	CVEIDEndpoint = "/cve-id"
	
	// CVE record endpoints  
	CVERecordEndpoint = "/cve"
	
	// Pagination defaults
	DefaultLimit    = 20
	MaxLimit       = 100
	DefaultOffset  = 0
)

// Query parameter names
const (
	ParamCVEID         = "cve_id"
	ParamState         = "state"  
	ParamAssignerOrgID = "assigner_org_id"
	ParamCountOnly     = "count_only"
	ParamLimit         = "limit"
	ParamOffset        = "offset"
	ParamTimeModified  = "time_modified.lt"
	ParamYear          = "cve_id_year"
)

// CVE ID year range
const (
	MinCVEYear = 1999
	MaxCVEYear = 2100 // Reasonable future limit
)

// HTTP Methods
const (
	MethodGet    = "GET"
	MethodPost   = "POST"
	MethodPut    = "PUT"
	MethodPatch  = "PATCH"
	MethodDelete = "DELETE"
)

// Content types
const (
	ContentTypeJSON = "application/json"
	ContentTypeForm = "application/x-www-form-urlencoded"
)

// CVE States for filtering
var ValidCVEStates = []CVEState{
	CVEStateReserved,
	CVEStatePublished, 
	CVEStateRejected,
}

// Reference tag types commonly used in CVE records
var CommonReferenceTags = []string{
	"Patch",
	"Third Party Advisory", 
	"VDB Entry",
	"Issue Tracking",
	"Exploit",
	"Technical Description",
	"Mitigation",
	"Vendor Advisory",
	"Tool Signature",
	"Mailing List",
	"Release Notes",
	"Product",
	"Not Applicable",
}