package organization

import (
	"encoding/json"
	"fmt"
	"strconv"

	"go.uber.org/zap"
)

const (
	// API endpoints
	OrgEndpoint  = "/org"
	UserEndpoint = "/org/users"
	
	// Defaults
	DefaultLimit  = 20
	MaxLimit     = 100
	DefaultOffset = 0
)

// GetOrganization retrieves organization information
func (c *Client) GetOrganization(orgID string) (*Organization, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization ID is required")
	}

	c.logger.Debug("Retrieving organization", zap.String("org_id", orgID))

	resp, err := c.baseClient.HTTP.R().
		Get(fmt.Sprintf("%s/%s", OrgEndpoint, orgID))

	if err != nil {
		c.logger.Error("Failed to get organization", zap.Error(err), zap.String("org_id", orgID))
		return nil, fmt.Errorf("failed to get organization %s: %w", orgID, err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("Organization request failed", 
			zap.String("org_id", orgID),
			zap.Int("status", resp.StatusCode()))
		return nil, fmt.Errorf("failed to get organization %s with status %d", orgID, resp.StatusCode())
	}

	var org Organization
	err = json.Unmarshal(resp.Body(), &org)
	if err != nil {
		c.logger.Error("Failed to unmarshal organization", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal organization: %w", err)
	}

	c.logger.Debug("Organization retrieved successfully", zap.String("org_id", orgID))
	return &org, nil
}

// ListUsers lists users in the organization
func (c *Client) ListUsers(limit, offset int) (*UserListResponse, error) {
	params := make(map[string]string)
	
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = DefaultOffset
	}
	
	params["limit"] = strconv.Itoa(limit)
	params["offset"] = strconv.Itoa(offset)

	c.logger.Debug("Listing users", zap.Int("limit", limit), zap.Int("offset", offset))

	resp, err := c.baseClient.HTTP.R().
		SetQueryParams(params).
		Get(UserEndpoint)

	if err != nil {
		c.logger.Error("Failed to list users", zap.Error(err))
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("User list request failed", zap.Int("status", resp.StatusCode()))
		return nil, fmt.Errorf("failed to list users with status %d", resp.StatusCode())
	}

	var userList UserListResponse
	err = json.Unmarshal(resp.Body(), &userList)
	if err != nil {
		c.logger.Error("Failed to unmarshal user list", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal user list: %w", err)
	}

	c.logger.Debug("Users listed successfully", zap.Int("count", len(userList.Users)))
	return &userList, nil
}

// GetUser retrieves a specific user
func (c *Client) GetUser(userID string) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	c.logger.Debug("Retrieving user", zap.String("user_id", userID))

	resp, err := c.baseClient.HTTP.R().
		Get(fmt.Sprintf("%s/%s", UserEndpoint, userID))

	if err != nil {
		c.logger.Error("Failed to get user", zap.Error(err), zap.String("user_id", userID))
		return nil, fmt.Errorf("failed to get user %s: %w", userID, err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("User request failed", 
			zap.String("user_id", userID),
			zap.Int("status", resp.StatusCode()))
		return nil, fmt.Errorf("failed to get user %s with status %d", userID, resp.StatusCode())
	}

	var user User
	err = json.Unmarshal(resp.Body(), &user)
	if err != nil {
		c.logger.Error("Failed to unmarshal user", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	c.logger.Debug("User retrieved successfully", zap.String("user_id", userID))
	return &user, nil
}

// CreateUser creates a new user
func (c *Client) CreateUser(request CreateUserRequest) (*User, error) {
	if request.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if request.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if request.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	c.logger.Debug("Creating user", zap.String("username", request.Username))

	resp, err := c.baseClient.HTTP.R().
		SetBody(request).
		Post(UserEndpoint)

	if err != nil {
		c.logger.Error("Failed to create user", zap.Error(err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("User creation failed", zap.Int("status", resp.StatusCode()))
		return nil, fmt.Errorf("failed to create user with status %d", resp.StatusCode())
	}

	var user User
	err = json.Unmarshal(resp.Body(), &user)
	if err != nil {
		c.logger.Error("Failed to unmarshal created user", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal created user: %w", err)
	}

	c.logger.Debug("User created successfully", 
		zap.String("user_id", user.ID), 
		zap.String("username", user.Username))
	return &user, nil
}

// UpdateUser updates an existing user
func (c *Client) UpdateUser(userID string, request UpdateUserRequest) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	c.logger.Debug("Updating user", zap.String("user_id", userID))

	resp, err := c.baseClient.HTTP.R().
		SetBody(request).
		Put(fmt.Sprintf("%s/%s", UserEndpoint, userID))

	if err != nil {
		c.logger.Error("Failed to update user", zap.Error(err), zap.String("user_id", userID))
		return nil, fmt.Errorf("failed to update user %s: %w", userID, err)
	}

	if !resp.IsSuccess() {
		c.logger.Error("User update failed", 
			zap.String("user_id", userID),
			zap.Int("status", resp.StatusCode()))
		return nil, fmt.Errorf("failed to update user %s with status %d", userID, resp.StatusCode())
	}

	var user User
	err = json.Unmarshal(resp.Body(), &user)
	if err != nil {
		c.logger.Error("Failed to unmarshal updated user", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal updated user: %w", err)
	}

	c.logger.Debug("User updated successfully", zap.String("user_id", userID))
	return &user, nil
}