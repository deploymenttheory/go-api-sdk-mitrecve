package cve

import (
	"time"
)

// CVEState represents the state of a CVE ID
type CVEState string

const (
	// CVE ID States
	CVEStateReserved  CVEState = "RESERVED"
	CVEStatePublished CVEState = "PUBLISHED"
	CVEStateRejected  CVEState = "REJECTED"
)

// CVERecord represents a complete CVE record
type CVERecord struct {
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	CVEMetadata CVEMetadata `json:"cveMetadata"`
	Containers  Containers  `json:"containers"`
}

// CVEMetadata contains metadata about the CVE
type CVEMetadata struct {
	CVEID              string     `json:"cveId"`
	AssignerOrgID      string     `json:"assignerOrgId"`
	AssignerShortName  string     `json:"assignerShortName,omitempty"`
	RequesterUserID    string     `json:"requesterUserId,omitempty"`
	DateUpdated        *time.Time `json:"dateUpdated,omitempty"`
	Serial             *int       `json:"serial,omitempty"`
	DateReserved       *time.Time `json:"dateReserved,omitempty"`
	DatePublished      *time.Time `json:"datePublished,omitempty"`
	DateRejected       *time.Time `json:"dateRejected,omitempty"`
	State              CVEState   `json:"state"`
	ReplacedBy         string     `json:"replacedBy,omitempty"`
	DateExpired        *time.Time `json:"dateExpired,omitempty"`
	OwningCNA          string     `json:"owningCna,omitempty"`
	SpecialConsiderations string  `json:"specialConsiderations,omitempty"`
}

// Containers holds the CVE record data containers
type Containers struct {
	CNA         *CNAContainer `json:"cna,omitempty"`
	ADP         []ADPContainer `json:"adp,omitempty"`
}

// CNAContainer represents data published by the CVE Numbering Authority
type CNAContainer struct {
	ProviderMetadata ProviderMetadata  `json:"providerMetadata"`
	Title            string           `json:"title,omitempty"`
	Descriptions     []Description    `json:"descriptions"`
	ProblemTypes     []ProblemType    `json:"problemTypes,omitempty"`
	Affected         []Affected       `json:"affected,omitempty"`
	References       []Reference      `json:"references,omitempty"`
	Impacts          []Impact         `json:"impacts,omitempty"`
	Workarounds      []Workaround     `json:"workarounds,omitempty"`
	Solutions        []Solution       `json:"solutions,omitempty"`
	Source           *Source          `json:"source,omitempty"`
	Exploits         []Exploit        `json:"exploits,omitempty"`
	Timeline         []Timeline       `json:"timeline,omitempty"`
	Credits          []Credit         `json:"credits,omitempty"`
	Tags             []Tag            `json:"tags,omitempty"`
	TaxonomyMappings []TaxonomyMapping `json:"taxonomyMappings,omitempty"`
	Configurations   []Configuration   `json:"configurations,omitempty"`
	Metrics          []Metric         `json:"metrics,omitempty"`
}

// ADPContainer represents data published by an Authorized Data Publisher
type ADPContainer struct {
	ProviderMetadata  ProviderMetadata  `json:"providerMetadata"`
	Title             string           `json:"title,omitempty"`
	Descriptions      []Description    `json:"descriptions,omitempty"`
	ProblemTypes      []ProblemType    `json:"problemTypes,omitempty"`
	Affected          []Affected       `json:"affected,omitempty"`
	References        []Reference      `json:"references,omitempty"`
	Impacts           []Impact         `json:"impacts,omitempty"`
	Metrics           []Metric         `json:"metrics,omitempty"`
	Configurations    []Configuration   `json:"configurations,omitempty"`
	TaxonomyMappings  []TaxonomyMapping `json:"taxonomyMappings,omitempty"`
}

// ProviderMetadata contains information about the provider
type ProviderMetadata struct {
	OrgID           string     `json:"orgId"`
	ShortName       string     `json:"shortName,omitempty"`
	DateUpdated     *time.Time `json:"dateUpdated,omitempty"`
	Serial          *int       `json:"serial,omitempty"`
}

// Description represents a textual description
type Description struct {
	Lang                 string                `json:"lang"`
	Value                string               `json:"value"`
	SupportingMedia      []SupportingMedia    `json:"supportingMedia,omitempty"`
}

// SupportingMedia represents supporting media for descriptions
type SupportingMedia struct {
	Type  string `json:"type"`
	Base64 bool  `json:"base64,omitempty"`
	Value string `json:"value"`
}

// ProblemType represents a problem type classification
type ProblemType struct {
	Descriptions []ProblemTypeDescription `json:"descriptions"`
}

// ProblemTypeDescription describes a problem type
type ProblemTypeDescription struct {
	Lang        string `json:"lang"`
	Description string `json:"description"`
	CWEID       string `json:"cweId,omitempty"`
	Type        string `json:"type,omitempty"`
	References  []Reference `json:"references,omitempty"`
}

// Affected represents affected products/versions
type Affected struct {
	Vendor           string           `json:"vendor,omitempty"`
	Product          string           `json:"product,omitempty"`
	CollectionURL    string           `json:"collectionURL,omitempty"`
	PackageName      string           `json:"packageName,omitempty"`
	CPES             []string         `json:"cpes,omitempty"`
	Modules          []string         `json:"modules,omitempty"`
	ProgramFiles     []string         `json:"programFiles,omitempty"`
	ProgramRoutines  []ProgramRoutine `json:"programRoutines,omitempty"`
	Platforms        []string         `json:"platforms,omitempty"`
	Repo             string           `json:"repo,omitempty"`
	Versions         []Version        `json:"versions,omitempty"`
	DefaultStatus    string           `json:"defaultStatus,omitempty"`
}

// ProgramRoutine represents a program routine
type ProgramRoutine struct {
	Name string `json:"name"`
}

// Version represents version information
type Version struct {
	Version         string  `json:"version"`
	Status          string  `json:"status"`
	VersionType     string  `json:"versionType,omitempty"`
	LessThan        string  `json:"lessThan,omitempty"`
	LessThanOrEqual string  `json:"lessThanOrEqual,omitempty"`
	Changes         []Change `json:"changes,omitempty"`
}

// Change represents a change in version status
type Change struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

// Reference represents a reference/link
type Reference struct {
	URL    string   `json:"url"`
	Name   string   `json:"name,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Impact represents impact information
type Impact struct {
	Descriptions []Description `json:"descriptions"`
	CapecID      string       `json:"capecId,omitempty"`
}

// Workaround represents workaround information
type Workaround struct {
	Lang            string           `json:"lang"`
	Value           string          `json:"value"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
}

// Solution represents solution information
type Solution struct {
	Lang            string           `json:"lang"`
	Value           string          `json:"value"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
}

// Source represents source information
type Source struct {
	Lang     string      `json:"lang,omitempty"`
	Value    string     `json:"value,omitempty"`
	Advisory string     `json:"advisory,omitempty"`
	Defect   []string   `json:"defect,omitempty"`
	Discovery string    `json:"discovery,omitempty"`
}

// Exploit represents exploit information
type Exploit struct {
	Lang            string           `json:"lang"`
	Value           string          `json:"value"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
}

// Timeline represents timeline events
type Timeline struct {
	Time  time.Time `json:"time"`
	Lang  string   `json:"lang"`
	Value string   `json:"value"`
}

// Credit represents credit information
type Credit struct {
	Lang     string `json:"lang"`
	Value    string `json:"value"`
	User     string `json:"user,omitempty"`
	Type     string `json:"type,omitempty"`
}

// Tag represents a tag
type Tag struct {
	Name string `json:"name"`
	Value string `json:"value,omitempty"`
}

// TaxonomyMapping represents taxonomy mapping information
type TaxonomyMapping struct {
	TaxonomyName    string         `json:"taxonomyName"`
	TaxonomyVersion string         `json:"taxonomyVersion,omitempty"`
	TaxonomyRelations []TaxonomyRelation `json:"taxonomyRelations"`
}

// TaxonomyRelation represents a taxonomy relation
type TaxonomyRelation struct {
	TaxonomyID   string `json:"taxonomyId"`
	Relationship string `json:"relationship"`
}

// Configuration represents configuration information
type Configuration struct {
	Lang            string           `json:"lang,omitempty"`
	Value           string          `json:"value,omitempty"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
}

// Metric represents metric information (CVSS, etc.)
type Metric struct {
	Format    string                 `json:"format"`
	Scenarios []Scenario            `json:"scenarios,omitempty"`
	Content   map[string]interface{} `json:"content"`
}

// Scenario represents a metric scenario
type Scenario struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// CVEListResponse represents the response from CVE list endpoints
type CVEListResponse struct {
	CVEIds      []string `json:"cveIds,omitempty"`
	TotalCount  int      `json:"totalCount"`
	ItemsPerPage int     `json:"itemsPerPage"`
	PageCount   int      `json:"pageCount"`
	CurrentPage int      `json:"currentPage"`
	PrevPage    string   `json:"prevPage,omitempty"`
	NextPage    string   `json:"nextPage,omitempty"`
	Format      string   `json:"format"`
	Version     string   `json:"version"`
	TimeStamp   time.Time `json:"timeStamp"`
	Warnings    []Warning `json:"warnings,omitempty"`
}

// Warning represents API warnings
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// CVEIDReservationRequest represents a CVE ID reservation request
type CVEIDReservationRequest struct {
	CVEYear    int    `json:"cve_year"`
	CVEIDCount int    `json:"cveid_count"`
	ShortName  string `json:"short_name"`
}

// CVEIDReservationResponse represents a CVE ID reservation response  
type CVEIDReservationResponse struct {
	CVEIds      []string `json:"cve_ids"`
	CVEYear     int      `json:"cve_year"`
	Message     string   `json:"message"`
	TimeReserved time.Time `json:"time_reserved"`
}