package main

// Bitwarden Key Sync main application.
// Retrieves public keys from Bitwarden and ensures they are added to the SSH authorized_keys file.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/avast/retry-go"
	"github.com/bitwarden/sdk-go"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Bitwarden struct {
		SecretID    string `yaml:"secret_id"`
		AccessToken string `yaml:"access_token"`
		ServerURL   string `yaml:"server_url"`
	} `yaml:"bitwarden"`
	SSHUser            string        `yaml:"ssh_user"`
	AuthorizedKeysFile string        `yaml:"authorized_keys_file,omitempty"`
	Interval           time.Duration `yaml:"interval"`
	AutoUpdate         struct {
		Enabled       bool          `yaml:"enabled"`
		CheckInterval time.Duration `yaml:"check_interval"`
	} `yaml:"auto_update"`
}

var logger = logrus.New()

func initLogger(logPath string) error {
	// Create log directory if needed
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Configure log rotation
	logger.SetOutput(&lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    100, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	})

	// Set log level from environment variable
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Use JSON format for structured logging
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})
	
	return nil
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validation
	if config.Bitwarden.SecretID == "" {
		return nil, errors.New("bitwarden.secret_id is required")
	}
	if config.Bitwarden.AccessToken == "" {
		return nil, errors.New("bitwarden.access_token is required")
	}
	if config.SSHUser == "" && config.AuthorizedKeysFile == "" {
		return nil, errors.New("ssh_user or authorized_keys_file is required")
	}
	if config.Interval == 0 {
		return nil, errors.New("interval must be greater than 0")
	}

	return &config, nil
}

// BitwardenClient defines the interface for Bitwarden operations
type BitwardenClient interface {
	AccessTokenLogin(accessToken string, stateFile *string) error
	GetSecretValue(id string) (string, error)
	Close()
}

// RealBitwardenClient wraps the SDK client
type RealBitwardenClient struct {
	client sdk.BitwardenClientInterface
}

func (c *RealBitwardenClient) AccessTokenLogin(accessToken string, stateFile *string) error {
	return c.client.AccessTokenLogin(accessToken, stateFile)
}

func (c *RealBitwardenClient) GetSecretValue(id string) (string, error) {
	resp, err := c.client.Secrets().Get(id)
	if err != nil {
		return "", err
	}
	return resp.Value, nil
}

func (c *RealBitwardenClient) Close() {
	c.client.Close()
}

// ClientCreator allows mocking the client creation
var NewBitwardenClient = func(apiURL, identityURL *string) (BitwardenClient, error) {
	c, err := sdk.NewBitwardenClient(apiURL, identityURL)
	if err != nil {
		return nil, err
	}
	return &RealBitwardenClient{client: c}, nil
}

// fetchPublicKey fetches the public key from Bitwarden Secrets Manager using the SDK
func fetchPublicKey(serverURL, secretID, accessToken string) (string, error) {
	apiURL := serverURL + "/api"
	identityURL := serverURL + "/identity"

	bitwardenClient, err := NewBitwardenClient(&apiURL, &identityURL)
	if err != nil {
		return "", fmt.Errorf("failed to create Bitwarden client: %w", err)
	}
	defer bitwardenClient.Close()

	stateFile := ".bitwarden_state"

	err = bitwardenClient.AccessTokenLogin(accessToken, &stateFile)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate with Bitwarden: %w", err)
	}

	value, err := bitwardenClient.GetSecretValue(secretID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch secret: %w", err)
	}

	key := strings.TrimSpace(value)
	if key == "" {
		return "", errors.New("empty public key received")
	}

	return key, nil
}

// resolveAuthorizedKeysPath determines the path to the authorized_keys file
func resolveAuthorizedKeysPath(config *Config) string {
	if config.AuthorizedKeysFile != "" {
		return config.AuthorizedKeysFile
	}
	if config.SSHUser == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return filepath.Join("/home", config.SSHUser, ".ssh", "authorized_keys")
}

// authorizedKeysPath returns the path to the authorized_keys file based on sshUser
func authorizedKeysPath(sshUser string) string {
	if sshUser == "root" {
		return "/root/.ssh/authorized_keys"
	}
	// Assuming typical Linux home directory structure
	return filepath.Join("/home", sshUser, ".ssh", "authorized_keys")
}

// readAuthorizedKeys reads the authorized_keys file and returns its lines
func readAuthorizedKeys(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	var lines []string
	if file != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		file.Close()
	}
	return lines, nil
}

// parseKeyComment extracts the comment from an SSH key
func parseKeyComment(key string) string {
	parts := strings.Split(key, " ")
	if len(parts) > 2 {
		return strings.Join(parts[2:], " ")
	}
	return ""
}

// processKeys ensures the bitwarden key exists in the authorized_keys list
func processKeys(existingLines []string, bitwardenKey string) []string {
	bitwardenComment := parseKeyComment(bitwardenKey)
	var newLines []string
	keyExists := false
	seenKeys := make(map[string]bool)

	for _, line := range existingLines {
		if line == bitwardenKey {
			if !seenKeys[line] {
				newLines = append(newLines, line)
				seenKeys[line] = true
			}
			keyExists = true
			continue
		}

		// Check if comment matches
		if parseKeyComment(line) == bitwardenComment {
			if !seenKeys[bitwardenKey] {
				newLines = append(newLines, bitwardenKey)
				seenKeys[bitwardenKey] = true
			}
			keyExists = true
		} else {
			if !seenKeys[line] {
				newLines = append(newLines, line)
				seenKeys[line] = true
			}
		}
	}

	// If key doesn't exist, append it
	if !keyExists {
		newLines = append(newLines, bitwardenKey)
	}

	return newLines
}

// writeAuthorizedKeys writes the authorized_keys file
func writeAuthorizedKeys(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
}

// ensureKeyInAuthorizedKeys orchestrates the process of ensuring a key exists in authorized_keys
func ensureKeyInAuthorizedKeys(authorizedKeysPath string, bitwardenKey string) error {
	existingLines, err := readAuthorizedKeys(authorizedKeysPath)
	if err != nil {
		return err
	}

	newLines := processKeys(existingLines, bitwardenKey)
	return writeAuthorizedKeys(authorizedKeysPath, newLines)
}

type ErrorCode int

const (
	ErrAuthFailed ErrorCode = iota + 1
	ErrNetworkError
	ErrInvalidResponse
	ErrFileSystemError
	ErrMaxRetriesExceeded
)

type SyncError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *SyncError) Error() string {
	return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Err)
}

// KeyFetcher defines the function signature for fetching keys
type KeyFetcher func(serverURL, secretID, accessToken string) (string, error)

var DefaultFetcher KeyFetcher = fetchPublicKey

func Run(ctx context.Context, config *Config, fetcher KeyFetcher) error {
	logger.Info("Starting Bitwarden Key Sync")

	logger.WithFields(logrus.Fields{
		"interval": config.Interval.String(),
	}).Info("Configuration loaded")

	// Start auto-update scheduler
	_ = startUpdateScheduler(config)

	// Run the first fetch immediately
	if err := fetchAndUpdate(config, fetcher); err != nil {
		return err
	}

	// Start the periodic fetch loop
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fetchAndUpdate(config, fetcher); err != nil {
				return err
			}
		case <-ctx.Done():
			logger.Info("Shutting down")
			return nil
		}
	}
}

// fetchAndUpdate retrieves the Bitwarden public key with retry logic and ensures it's present in authorized_keys.
func fetchAndUpdate(config *Config, fetcher KeyFetcher) error {
	secretID := config.Bitwarden.SecretID
	token := config.Bitwarden.AccessToken
	serverURL := config.Bitwarden.ServerURL
	// sshUser usage is replaced by resolveAuthorizedKeysPath logic

	logger.WithFields(logrus.Fields{
		"secretID":  secretID,
		"serverURL": serverURL,
		"sshUser":   config.SSHUser,
	}).Debug("Environment variables loaded")

	var publicKey string
	err := retry.Do(
		func() error {
			var err error
			publicKey, err = fetcher(serverURL, secretID, token)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			logger.Infof("Retry attempt %d: %v", n+1, err)
		}),
	)
	if err != nil {
		return &SyncError{Code: ErrNetworkError, Message: "Failed to fetch public key", Err: err}
	}

	logger.Debug("Public key fetched successfully")
	authKeysPath := resolveAuthorizedKeysPath(config)
	logger.WithField("authKeysPath", authKeysPath).Debug("Authorized keys path resolved")

	logger.Debug("Ensuring public key is present in authorized_keys")
	err = ensureKeyInAuthorizedKeys(authKeysPath, publicKey)
	if err != nil {
		return &SyncError{Code: ErrFileSystemError, Message: "Failed to update authorized_keys", Err: err}
	}

	return nil
}

func main() {
	if err := runApp(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runApp(args []string) error {
	var configPath string
	var logPath string
	
	// Use a FlagSet to avoid polluting global flags in tests
	fs := flag.NewFlagSet("bwkeysync", flag.ContinueOnError)
	fs.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	fs.StringVar(&logPath, "log-file", "/var/log/bwkeysync.log", "Path to log file")
	
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if err := initLogger(logPath); err != nil {
		return err
	}

	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, config, DefaultFetcher); err != nil {
		// If the context was canceled, it's a normal shutdown, not an error
		if !errors.Is(ctx.Err(), context.Canceled) {
			return err
		}
	}
	return nil
}
