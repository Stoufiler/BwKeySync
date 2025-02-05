package main

// Bitwarden Key Sync main application.
// Retrieves public keys from Bitwarden and ensures they are added to the SSH authorized_keys file.

import (
	"bufio"
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
	SSHUser  string        `yaml:"ssh_user"`
	Interval time.Duration `yaml:"interval"`
}

var logger = logrus.New()

func initLogger() {
	// Configure log rotation
	logger.SetOutput(&lumberjack.Logger{
		Filename:   "bwkeysync.log",
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     30, // days
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
	if config.SSHUser == "" {
		return nil, errors.New("ssh_user is required")
	}
	if config.Interval == 0 {
		return nil, errors.New("interval must be greater than 0")
	}

	return &config, nil
}

// fetchPublicKey fetches the public key from Bitwarden Secrets Manager using the SDK
func fetchPublicKey(serverURL, secretID, accessToken string) (string, error) {
	apiURL := serverURL + "/api"
	identityURL := serverURL + "/identity"

	bitwardenClient, err := sdk.NewBitwardenClient(&apiURL, &identityURL)
	if err != nil {
		return "", fmt.Errorf("failed to create Bitwarden client: %w", err)
	}
	defer bitwardenClient.Close()

	stateFile := ".bitwarden_state"

	err = bitwardenClient.AccessTokenLogin(accessToken, &stateFile)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate with Bitwarden: %w", err)
	}

	secret, err := bitwardenClient.Secrets().Get(secretID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch secret: %w", err)
	}

	key := strings.TrimSpace(secret.Value)
	if key == "" {
		return "", errors.New("empty public key received")
	}

	return key, nil
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

func Run(config *Config) error {
	initLogger()
	logger.Info("Starting Bitwarden Key Sync")

	logger.WithFields(logrus.Fields{
		"interval": config.Interval.String(),
	}).Info("Configuration loaded")

	// Set up signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Run the first fetch immediately
	if err := fetchAndUpdate(config); err != nil {
		return err
	}

	// Start the periodic fetch loop
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fetchAndUpdate(config); err != nil {
				return err
			}
		case <-sigs:
			logger.Info("Shutting down")
			return nil
		}
	}
}

// fetchAndUpdate retrieves the Bitwarden public key with retry logic and ensures it's present in authorized_keys.
func fetchAndUpdate(config *Config) error {
	secretID := config.Bitwarden.SecretID
	token := config.Bitwarden.AccessToken
	serverURL := config.Bitwarden.ServerURL
	sshUser := config.SSHUser

	logger.WithFields(logrus.Fields{
		"secretID":  secretID,
		"serverURL": serverURL,
		"sshUser":   sshUser,
	}).Debug("Environment variables loaded")

	var publicKey string
	err := retry.Do(
		func() error {
			var err error
			publicKey, err = fetchPublicKey(serverURL, secretID, token)
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
	authKeysPath := authorizedKeysPath(sshUser)
	logger.WithField("authKeysPath", authKeysPath).Debug("Authorized keys path resolved")

	logger.Debug("Ensuring public key is present in authorized_keys")
	err = ensureKeyInAuthorizedKeys(authKeysPath, publicKey)
	if err != nil {
		return &SyncError{Code: ErrFileSystemError, Message: "Failed to update authorized_keys", Err: err}
	}

	return nil
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	flag.Parse()

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	if err := Run(config); err != nil {
		log.Fatal(err)
	}
}
