package organization

import (
	"github.com/deploymenttheory/go-api-sdk-mitrecve/client"
	"go.uber.org/zap"
)

// Client represents the organization service client
type Client struct {
	baseClient *client.Client
	logger     *zap.Logger
}

// NewClient creates a new organization service client
func NewClient(baseClient *client.Client) *Client {
	return &Client{
		baseClient: baseClient,
		logger:     baseClient.Logger,
	}
}

// NewDefaultClient creates a new organization service client with default configuration
func NewDefaultClient() *Client {
	return NewClient(client.NewDefaultClient())
}

// NewClientWithAuth creates a new organization service client with authentication
func NewClientWithAuth(apiKey, secretKey string) *Client {
	return NewClient(client.NewClientWithAuth(apiKey, secretKey))
}

// Close properly closes the client and flushes logs
func (c *Client) Close() {
	if c.baseClient != nil {
		c.baseClient.Close()
	}
}