package client

import (
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// BaseURL is the MITRE CVE Services API base URL
	BaseURL = "https://cveawg.mitre.org/api"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
	// DefaultRetryCount is the default number of retry attempts
	DefaultRetryCount = 3
	// DefaultRetryDelay is the default delay between retries
	DefaultRetryDelay = 1 * time.Second
	// DefaultUserAgent is the default User-Agent header
	DefaultUserAgent = "go-api-sdk-mitrecve/1.0.0"
)

// Client represents the MITRE CVE API client
type Client struct {
	HTTP   *resty.Client
	Logger *zap.Logger
	Config Config
}

// Config holds the configuration for the CVE API client
type Config struct {
	BaseURL    string
	OrgID      string // CVE-API-ORG header (required)
	Username   string // CVE-API-USER header (required for authenticated operations)
	APIKey     string // CVE-API-KEY header (required for authenticated operations)
	SecretKey  string // Secret key for basic authentication
	Timeout    time.Duration
	RetryCount int
	RetryDelay time.Duration
	UserAgent  string
	Debug      bool
}

// NewClient creates a new CVE API client with the given configuration
func NewClient(config Config) *Client {
	var logger *zap.Logger
	var err error

	if config.Debug {
		// Development config with colors and console encoder
		developmentConfig := zap.NewDevelopmentConfig()
		developmentConfig.EncoderConfig.EncodeLevel = zapcore.LowercaseColorLevelEncoder
		developmentConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		developmentConfig.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
		logger, err = developmentConfig.Build()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		logger = zap.NewNop()
	}

	// Set defaults if not provided
	if config.BaseURL == "" {
		config.BaseURL = BaseURL
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.RetryCount == 0 {
		config.RetryCount = DefaultRetryCount
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = DefaultRetryDelay
	}
	if config.UserAgent == "" {
		config.UserAgent = DefaultUserAgent
	}

	httpClient := resty.New().
		SetBaseURL(config.BaseURL).
		SetTimeout(config.Timeout).
		SetRetryCount(config.RetryCount).
		SetRetryWaitTime(config.RetryDelay).
		SetHeader("User-Agent", config.UserAgent).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json")

	// Set authentication if provided
	if config.APIKey != "" && config.SecretKey != "" {
		httpClient.SetBasicAuth(config.APIKey, config.SecretKey)
	}

	if config.Debug {
		httpClient.SetDebug(true)
	}

	return &Client{
		HTTP:   httpClient,
		Logger: logger,
		Config: config,
	}
}

// NewDefaultClient creates a new CVE API client with default configuration
func NewDefaultClient() *Client {
	return NewClient(Config{})
}

// NewClientWithAuth creates a new CVE API client with authentication
func NewClientWithAuth(apiKey, secretKey string) *Client {
	return NewClient(Config{
		APIKey:    apiKey,
		SecretKey: secretKey,
	})
}

// Close properly closes the client and flushes logs
func (c *Client) Close() {
	if c.Logger != nil {
		c.Logger.Sync()
	}
}

// SetDebug enables or disables debug mode
func (c *Client) SetDebug(debug bool) {
	c.Config.Debug = debug
	c.HTTP.SetDebug(debug)
}

// SetAuth sets the API credentials for authentication
func (c *Client) SetAuth(apiKey, secretKey string) {
	c.Config.APIKey = apiKey
	c.Config.SecretKey = secretKey
	c.HTTP.SetBasicAuth(apiKey, secretKey)
}
