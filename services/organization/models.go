package organization

import "time"

// Organization represents an organization in the CVE system
type Organization struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	ShortName         string    `json:"short_name"`
	Website           string    `json:"website,omitempty"`
	ContactEmail      string    `json:"contact_email,omitempty"`
	Active            bool      `json:"active"`
	IsCNA             bool      `json:"is_cna"`
	IsADP             bool      `json:"is_adp"`
	IsSecretariat     bool      `json:"is_secretariat"`
	CVEIDQuota        int       `json:"cveid_quota"`
	CVEIDUsed         int       `json:"cveid_used"`
	DateCreated       time.Time `json:"date_created"`
	DateLastModified  time.Time `json:"date_last_modified"`
}

// User represents a user in the CVE system
type User struct {
	ID               string    `json:"id"`
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	Active           bool      `json:"active"`
	OrganizationID   string    `json:"organization_id"`
	Roles            []string  `json:"roles"`
	DateCreated      time.Time `json:"date_created"`
	DateLastModified time.Time `json:"date_last_modified"`
	LastLogin        *time.Time `json:"last_login,omitempty"`
}

// UserRole represents user roles in the system
type UserRole string

const (
	RoleAdmin       UserRole = "ADMIN"
	RoleUser        UserRole = "USER"
	RoleSecretariat UserRole = "SECRETARIAT"
)

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	FirstName    string   `json:"first_name"`
	LastName     string   `json:"last_name"`
	Password     string   `json:"password"`
	Roles        []string `json:"roles"`
}

// UpdateUserRequest represents a request to update user information
type UpdateUserRequest struct {
	Email     *string  `json:"email,omitempty"`
	FirstName *string  `json:"first_name,omitempty"`
	LastName  *string  `json:"last_name,omitempty"`
	Active    *bool    `json:"active,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// OrganizationListResponse represents the response for organization listings
type OrganizationListResponse struct {
	Organizations []Organization `json:"organizations"`
	TotalCount    int           `json:"total_count"`
	ItemsPerPage  int           `json:"items_per_page"`
	PageCount     int           `json:"page_count"`
	CurrentPage   int           `json:"current_page"`
}

// UserListResponse represents the response for user listings  
type UserListResponse struct {
	Users        []User `json:"users"`
	TotalCount   int    `json:"total_count"`
	ItemsPerPage int    `json:"items_per_page"`
	PageCount    int    `json:"page_count"`
	CurrentPage  int    `json:"current_page"`
}