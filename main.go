package main

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

// ensureKeyInAuthorizedKeys appends the public key to authorized_keys if not already present
func ensureKeyInAuthorizedKeys(authorizedKeysPath string, bitwardenKey string) error {
	// Read existing authorized_keys file
	file, err := os.Open(authorizedKeysPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var existingLines []string
	if file != nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			existingLines = append(existingLines, scanner.Text())
		}
		file.Close()
	}

	// Parse Bitwarden key and comment
	bitwardenParts := strings.Split(bitwardenKey, " ")
	bitwardenComment := ""
	if len(bitwardenParts) > 2 {
		bitwardenComment = strings.Join(bitwardenParts[2:], " ")
	}

	// Process existing lines
	var newLines []string
	keyExists := false
	for _, line := range existingLines {
		if line == bitwardenKey {
			// Exact match, keep as is
			newLines = append(newLines, line)
			keyExists = true
			continue
		}

		// Check if comment matches
		parts := strings.Split(line, " ")
		if len(parts) > 2 && strings.Join(parts[2:], " ") == bitwardenComment {
			// Comment matches but key differs, replace with Bitwarden key
			newLines = append(newLines, bitwardenKey)
			keyExists = true
		} else {
			// Keep original line
			newLines = append(newLines, line)
		}
	}

	// If key doesn't exist, append it
	if !keyExists {
		newLines = append(newLines, bitwardenKey)
	}

	// Write updated file
	return os.WriteFile(authorizedKeysPath, []byte(strings.Join(newLines, "\n")), 0600)
}

const (
	maxRetries        = 3
	initialBackoff    = 1 * time.Second
	maxBackoff        = 30 * time.Second
	backoffMultiplier = 2.0
	jitterFactor      = 0.1
)

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

func withRetry(fn func() error, operation string) error {
	var lastErr error
	backoff := initialBackoff

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err
		logger.WithFields(logrus.Fields{
			"attempt":   attempt,
			"operation": operation,
			"backoff":   backoff.String(),
		}).Warn("Operation failed, retrying")

		if attempt < maxRetries {
			time.Sleep(backoff)
			backoff = time.Duration(float64(backoff) * backoffMultiplier)

			jitter := time.Duration(float64(backoff) * jitterFactor)
			if attempt%2 == 0 {
				backoff += jitter
			} else {
				backoff -= jitter
			}

			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	return &SyncError{
		Code:    ErrMaxRetriesExceeded,
		Message: fmt.Sprintf("Max retries (%d) exceeded for operation: %s", maxRetries, operation),
		Err:     lastErr,
	}
}

// Run starts the application
func Run() error {
	initLogger()
	logger.Info("Starting Bitwarden Key Sync")

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

func fetchAndUpdate() error {
	return withRetry(func() error {
		logger.Debug("Starting fetch and update process")

		secretID, err := getEnv("BW_SECRET_ID")
		if err != nil {
			return &SyncError{Code: ErrAuthFailed, Message: "Failed to read BW_SECRET_ID", Err: err}
		}

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

		logger.Debug("Fetching public key from Bitwarden")
		publicKey, err := fetchPublicKey(serverURL, secretID, token)
		if err != nil {
			return &SyncError{Code: ErrNetworkError, Message: "Failed to fetch public key", Err: err}
		}

		logger.Debug("Public key fetched successfully")

		authKeysPath := authorizedKeysPath(sshUser)

		logger.WithField("authKeysPath", authKeysPath).Debug("Authorized keys path resolved")

		logger.Debug("Ensuring public key is present in authorized_keys")
		return ensureKeyInAuthorizedKeys(authKeysPath, publicKey)
	}, "fetchAndUpdate")
}

func main() {
	if err := Run(); err != nil {
		log.Fatal(err)
	}
}
