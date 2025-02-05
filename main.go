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
)

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

// getEnv retrieves an environment variable and returns an error if not present
func getEnv(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value, nil
	}
	return "", fmt.Errorf("environment variable %s not set", key)
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

	stateFile := os.Getenv("STATE_FILE")
	if stateFile == "" {
		stateFile = ".bitwarden_state"
	}

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

func checkEnvVars() error {
	requiredVars := []string{"BW_SECRET_ID", "BW_ACCESS_TOKEN", "BW_SERVER_URL", "BW_SSH_USER"}
	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("required environment variable %s not set", envVar)
		}
	}
	return nil
}

// Run starts the application
func Run() error {
	initLogger()
	logger.Info("Starting Bitwarden Key Sync")

	if err := checkEnvVars(); err != nil {
		logger.Error(err)
		return err
	}

	interval := flag.Duration("interval", 10*time.Minute, "Interval between public key fetches (in minutes)")
	flag.Parse()

	logger.WithFields(logrus.Fields{
		"interval": interval.String(),
	}).Info("Configuration loaded")

	// Set up signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Run the first fetch immediately
	if err := fetchAndUpdate(); err != nil {
		return err
	}

	// Start the periodic fetch loop
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fetchAndUpdate(); err != nil {
				return err
			}
		case <-sigs:
			logger.Info("Shutting down")
			return nil
		}
	}
}

// fetchAndUpdate retrieves the Bitwarden public key with retry logic and ensures it's present in authorized_keys.
func fetchAndUpdate() error {
	secretID := os.Getenv("BW_SECRET_ID")
	token, err := getEnv("BW_ACCESS_TOKEN")
	if err != nil {
		return &SyncError{Code: ErrAuthFailed, Message: "Failed to read BW_ACCESS_TOKEN", Err: err}
	}

	serverURL, err := getEnv("BW_SERVER_URL")
	if err != nil {
		return &SyncError{Code: ErrAuthFailed, Message: "Failed to read BW_SERVER_URL", Err: err}
	}

	sshUser, err := getEnv("BW_SSH_USER")
	if err != nil {
		return &SyncError{Code: ErrAuthFailed, Message: "Failed to read BW_SSH_USER", Err: err}
	}

	logger.WithFields(logrus.Fields{
		"secretID":  secretID,
		"serverURL": serverURL,
		"sshUser":   sshUser,
	}).Debug("Environment variables loaded")

	var publicKey string
	err = retry.Do(
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
	if err := Run(); err != nil {
		log.Fatal(err)
	}
}
