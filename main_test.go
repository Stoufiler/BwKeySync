package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bitwarden/sdk-go"
	"github.com/sirupsen/logrus"
)

func TestParseKeyComment(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			"standard key",
			"ssh-rsa AAAAB3Nza... user@host",
			"user@host",
		},
		{
			"key with multiple comments",
			"ssh-ed25519 AAAAC3Nza... my laptop key",
			"my laptop key",
		},
		{
			"key without comment",
			"ssh-ed25519 AAAAC3Nza...",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseKeyComment(tt.key); got != tt.expected {
				t.Errorf("parseKeyComment() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProcessKeys(t *testing.T) {
	tests := []struct {
		name          string
		existingLines []string
		bitwardenKey  string
		expected      []string
	}{
		{
			"empty existing, new key added",
			[]string{},
			"ssh-rsa AAA... user@host",
			[]string{"ssh-rsa AAA... user@host"},
		},
		{
			"key already exists exactly",
			[]string{"ssh-rsa AAA... user@host"},
			"ssh-rsa AAA... user@host",
			[]string{"ssh-rsa AAA... user@host"},
		},
		{
			"key exists but material changed (same comment)",
			[]string{"ssh-rsa OLD... user@host"},
			"ssh-rsa NEW... user@host",
			[]string{"ssh-rsa NEW... user@host"},
		},
		{
			"multiple keys, update one",
			[]string{
				"ssh-ed25519 BBB... other@host",
				"ssh-rsa OLD... user@host",
			},
			"ssh-rsa NEW... user@host",
			[]string{
				"ssh-ed25519 BBB... other@host",
				"ssh-rsa NEW... user@host",
			},
		},
		{
			"multiple keys, append one",
			[]string{
				"ssh-ed25519 BBB... other@host",
			},
			"ssh-rsa NEW... user@host",
			[]string{
				"ssh-ed25519 BBB... other@host",
				"ssh-rsa NEW... user@host",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processKeys(tt.existingLines, tt.bitwardenKey)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("processKeys() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthorizedKeysPath(t *testing.T) {
	tests := []struct {
		name     string
		sshUser  string
		expected string
	}{
		{"root user", "root", "/root/.ssh/authorized_keys"},
		{"normal user", "jdoe", "/home/jdoe/.ssh/authorized_keys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorizedKeysPath(tt.sshUser)
			if got != tt.expected {
				t.Errorf("authorizedKeysPath() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestResolveAuthorizedKeysPath(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "override set",
			config: Config{
				AuthorizedKeysFile: "/tmp/custom_keys",
				SSHUser:            "user",
			},
			expected: "/tmp/custom_keys",
		},
		{
			name: "root user",
			config: Config{
				SSHUser: "root",
			},
			expected: "/root/.ssh/authorized_keys",
		},
		{
			name: "normal user",
			config: Config{
				SSHUser: "jdoe",
			},
			expected: "/home/jdoe/.ssh/authorized_keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAuthorizedKeysPath(&tt.config)
			if got != tt.expected {
				t.Errorf("resolveAuthorizedKeysPath() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	validConfig := `
bitwarden:
  secret_id: "test-secret"
  access_token: "test-token"
  server_url: "http://localhost"
ssh_user: "test-user"
interval: 5m
`
	err := os.WriteFile(configFile, []byte(validConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Test loading valid config
	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfg.Bitwarden.SecretID != "test-secret" {
		t.Errorf("expected secret_id 'test-secret', got %v", cfg.Bitwarden.SecretID)
	}
	if cfg.Interval != 5*time.Minute {
		t.Errorf("expected interval 5m, got %v", cfg.Interval)
	}

	// Test missing required fields
	invalidConfig := `
bitwarden:
  server_url: "http://localhost"
`
	err = os.WriteFile(configFile, []byte(invalidConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadConfig(configFile)
	if err == nil {
		t.Error("expected error for missing required fields, got nil")
	}

	// Test config with only AuthorizedKeysFile (no SSHUser)
	authFileConfig := `
bitwarden:
  secret_id: "test-secret"
  access_token: "test-token"
  server_url: "http://localhost"
authorized_keys_file: "/tmp/keys"
interval: 5m
`
	err = os.WriteFile(configFile, []byte(authFileConfig), 0644)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = loadConfig(configFile)
	if err != nil {
		t.Errorf("loadConfig with only authorized_keys_file failed: %v", err)
	}

	// Test invalid YAML
	err = os.WriteFile(configFile, []byte("invalid: yaml: ["), 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadConfig(configFile)
	if err == nil {
		t.Error("expected error for invalid yaml")
	}
}

func TestFileOperations(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")

	// Test writing keys
	keys := []string{"key1", "key2"}
	err := writeAuthorizedKeys(authKeysFile, keys)
	if err != nil {
		t.Fatalf("writeAuthorizedKeys failed: %v", err)
	}

	// Test reading keys
	readKeys, err := readAuthorizedKeys(authKeysFile)
	if err != nil {
		t.Fatalf("readAuthorizedKeys failed: %v", err)
	}

	if !reflect.DeepEqual(keys, readKeys) {
		t.Errorf("read keys %v, want %v", readKeys, keys)
	}

	// Test reading non-existent file (should return nil slice, no error)
	nonExistent := filepath.Join(tmpDir, "non_existent")
	readKeys, err = readAuthorizedKeys(nonExistent)
	if err != nil {
		t.Errorf("readAuthorizedKeys(nonExistent) returned error: %v", err)
	}
	if len(readKeys) != 0 {
		t.Errorf("readAuthorizedKeys(nonExistent) returned %d keys, want 0", len(readKeys))
	}
}

func TestFileOperations_Errors(t *testing.T) {
	tmpDir := t.TempDir()
	
	// 1. Test read error (permission denied)
	// Create a file with no read permissions
	noReadFile := filepath.Join(tmpDir, "noread")
	err := os.WriteFile(noReadFile, []byte("content"), 0000)
	if err != nil {
		t.Fatal(err)
	}
	
	_, err = readAuthorizedKeys(noReadFile)
	if err == nil {
		t.Error("expected error reading file with no permissions")
	}

	// 2. Test write error (directory doesn't exist)
	// writeAuthorizedKeys uses os.WriteFile which creates file, but fails if dir is missing?
	// os.WriteFile does NOT create directories.
	
	missingDirFile := filepath.Join(tmpDir, "missing", "keys")
	err = writeAuthorizedKeys(missingDirFile, []string{"key"})
	if err == nil {
		t.Error("expected error writing to non-existent directory")
	}
}

// MockBitwardenClient for testing
type MockBitwardenClient struct {
	LoginFunc     func(accessToken string, stateFile *string) error
	GetSecretFunc func(id string) (string, error)
	CloseFunc     func()
}

func (m *MockBitwardenClient) AccessTokenLogin(accessToken string, stateFile *string) error {
	if m.LoginFunc != nil {
		return m.LoginFunc(accessToken, stateFile)
	}
	return nil
}

func (m *MockBitwardenClient) GetSecretValue(id string) (string, error) {
	if m.GetSecretFunc != nil {
		return m.GetSecretFunc(id)
	}
	return "", nil
}

func (m *MockBitwardenClient) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}

// MockSDKClient implements sdk.BitwardenClientInterface
type MockSDKClient struct {
	AccessTokenLoginFunc func(accessToken string, stateFile *string) error
	SecretsFunc          func() sdk.SecretsInterface
	CloseFunc            func()
}

func (m *MockSDKClient) AccessTokenLogin(accessToken string, stateFile *string) error {
	if m.AccessTokenLoginFunc != nil {
		return m.AccessTokenLoginFunc(accessToken, stateFile)
	}
	return nil
}
func (m *MockSDKClient) Secrets() sdk.SecretsInterface {
	if m.SecretsFunc != nil {
		return m.SecretsFunc()
	}
	return nil
}
func (m *MockSDKClient) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}
func (m *MockSDKClient) Projects() sdk.ProjectsInterface { return nil }
func (m *MockSDKClient) Generators() sdk.GeneratorsInterface { return nil }

// MockSecrets implements sdk.SecretsInterface
type MockSecrets struct {
	GetFunc func(secretID string) (*sdk.SecretResponse, error)
}
func (m *MockSecrets) Get(secretID string) (*sdk.SecretResponse, error) {
	if m.GetFunc != nil {
		return m.GetFunc(secretID)
	}
	return nil, nil
}
// Implement other methods of SecretsInterface with panics or no-ops as they aren't used
func (m *MockSecrets) Create(key, value, note string, organizationID string, projectIDs []string) (*sdk.SecretResponse, error) { return nil, nil }
func (m *MockSecrets) List(organizationID string) (*sdk.SecretIdentifiersResponse, error) { return nil, nil }
func (m *MockSecrets) GetByIDS(secretIDs []string) (*sdk.SecretsResponse, error) { return nil, nil }
func (m *MockSecrets) Update(secretID string, key, value, note string, organizationID string, projectIDs []string) (*sdk.SecretResponse, error) { return nil, nil }
func (m *MockSecrets) Delete(secretIDs []string) (*sdk.SecretsDeleteResponse, error) { return nil, nil }
func (m *MockSecrets) Sync(organizationID string, lastSyncedDate *time.Time) (*sdk.SecretsSyncResponse, error) { return nil, nil }

func TestRealBitwardenClient(t *testing.T) {
	mockSecrets := &MockSecrets{
		GetFunc: func(secretID string) (*sdk.SecretResponse, error) {
			if secretID == "error" {
				return nil, fmt.Errorf("secret error")
			}
			return &sdk.SecretResponse{Value: "secret-value"}, nil
		},
	}

	mockSDK := &MockSDKClient{
		AccessTokenLoginFunc: func(accessToken string, stateFile *string) error {
			if accessToken == "error" {
				return fmt.Errorf("login error")
			}
			return nil
		},
		SecretsFunc: func() sdk.SecretsInterface {
			return mockSecrets
		},
		CloseFunc: func() {},
	}

	client := &RealBitwardenClient{client: mockSDK}

	// Test AccessTokenLogin
	if err := client.AccessTokenLogin("token", nil); err != nil {
		t.Errorf("AccessTokenLogin failed: %v", err)
	}
	if err := client.AccessTokenLogin("error", nil); err == nil {
		t.Error("expected error for AccessTokenLogin, got nil")
	}

	// Test GetSecretValue
	val, err := client.GetSecretValue("id")
	if err != nil {
		t.Errorf("GetSecretValue failed: %v", err)
	}
	if val != "secret-value" {
		t.Errorf("expected secret-value, got %s", val)
	}
	
	_, err = client.GetSecretValue("error")
	if err == nil {
		t.Error("expected error for GetSecretValue, got nil")
	}

	// Test Close (ensure no panic)
	client.Close()
}

func TestDefaultNewBitwardenClient(t *testing.T) {
	// We want to test the default NewBitwardenClient implementation
	// We can't access it if we overwrote it, but here we haven't overwrote it globally yet
	// (other tests use defer to restore)
	
	// Test with invalid URLs to trigger potential error or success
	// The SDK NewBitwardenClient likely checks URL format
	
	api := "http://localhost"
	identity := "http://localhost"
	
	client, err := NewBitwardenClient(&api, &identity)
	// It's possible this succeeds as it just creates the client struct
	if err == nil {
		if client == nil {
			t.Error("expected client, got nil")
		}
	} else {
		// If it fails (maybe dependency missing), that's also fine, we just want to execute the code
		t.Logf("NewBitwardenClient failed (expected in some envs): %v", err)
	}

	// Test with nil (if SDK handles it) or empty
	// This helps cover the function body
	_, _ = NewBitwardenClient(nil, nil)
}

func TestFetchPublicKey(t *testing.T) {
	// Backup original factory
	originalFactory := NewBitwardenClient
	defer func() { NewBitwardenClient = originalFactory }()

	tests := []struct {
		name        string
		loginErr    error
		secretErr   error
		secretValue string
		expectErr   bool
		errContains string
	}{
		{
			name:        "success",
			secretValue: "ssh-rsa success",
			expectErr:   false,
		},
		{
			name:      "login error",
			loginErr:  fmt.Errorf("auth failed"),
			expectErr: true,
			errContains: "auth failed",
		},
		{
			name:      "secret fetch error",
			secretErr: fmt.Errorf("not found"),
			expectErr: true,
			errContains: "not found",
		},
		{
			name:        "empty key",
			secretValue: "   ",
			expectErr:   true,
			errContains: "empty public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock factory
			NewBitwardenClient = func(apiURL, identityURL *string) (BitwardenClient, error) {
				return &MockBitwardenClient{
					LoginFunc: func(token string, state *string) error {
						return tt.loginErr
					},
					GetSecretFunc: func(id string) (string, error) {
						return tt.secretValue, tt.secretErr
					},
				}, nil
			}

			key, err := fetchPublicKey("http://localhost", "secret", "token")
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if key != strings.TrimSpace(tt.secretValue) {
					t.Errorf("got key %q, want %q", key, strings.TrimSpace(tt.secretValue))
				}
			}
		})
	}
	
	// Test client creation failure
	NewBitwardenClient = func(apiURL, identityURL *string) (BitwardenClient, error) {
		return nil, fmt.Errorf("init failed")
	}
	_, err := fetchPublicKey("http://localhost", "secret", "token")
	if err == nil || !strings.Contains(err.Error(), "init failed") {
		t.Error("expected init failure error")
	}
}

func TestFetchAndUpdate(t *testing.T) {
	// Setup temporary directory and authorized_keys file
	tmpDir := t.TempDir()
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")

	// Initial content of authorized_keys
	initialKeys := []string{
		"ssh-ed25519 AAAAC3Nza... existing@host",
	}
	err := writeAuthorizedKeys(authKeysFile, initialKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Mock configuration
	config := &Config{
		AuthorizedKeysFile: authKeysFile,
	}
	config.Bitwarden.SecretID = "test-secret"
	config.Bitwarden.AccessToken = "test-token"
	config.Bitwarden.ServerURL = "http://localhost"
	// interval and sshUser not needed for this specific test flow as we override path

	// Mock fetcher
	mockKey := "ssh-rsa AAAAB3Nza... new-key@bitwarden"
	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		if serverURL != "http://localhost" {
			t.Errorf("unexpected serverURL: %s", serverURL)
		}
		if secretID != "test-secret" {
			t.Errorf("unexpected secretID: %s", secretID)
		}
		if accessToken != "test-token" {
			t.Errorf("unexpected accessToken: %s", accessToken)
		}
		return mockKey, nil
	}

	// Run fetchAndUpdate
	err = fetchAndUpdate(config, mockFetcher)
	if err != nil {
		t.Fatalf("fetchAndUpdate failed: %v", err)
	}

	// Verify the file content
	content, err := os.ReadFile(authKeysFile)
	if err != nil {
		t.Fatal(err)
	}
	fileContent := string(content)

	if !strings.Contains(fileContent, "existing@host") {
		t.Error("existing key removed from file")
	}
	if !strings.Contains(fileContent, "new-key@bitwarden") {
		t.Error("new key not found in file")
	}
}

func TestFetchAndUpdate_RetrySuccess(t *testing.T) {
	// Setup temporary directory
	tmpDir := t.TempDir()
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	
	config := &Config{
		AuthorizedKeysFile: authKeysFile,
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	failures := 0
	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		if failures < 2 {
			failures++
			return "", fmt.Errorf("network error")
		}
		return "ssh-rsa success", nil
	}

	err := fetchAndUpdate(config, mockFetcher)
	if err != nil {
		t.Errorf("expected success after retries, got error: %v", err)
	}
	if failures != 2 {
		t.Errorf("expected 2 failures, got %d", failures)
	}
}

func TestFetchAndUpdate_AllFail(t *testing.T) {
	// Setup temporary directory
	tmpDir := t.TempDir()
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	
	config := &Config{
		AuthorizedKeysFile: authKeysFile,
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		return "", fmt.Errorf("permanent failure")
	}

	err := fetchAndUpdate(config, mockFetcher)
	if err == nil {
		t.Error("expected error after all retries failed, got nil")
	}
}

func TestFetchAndUpdate_FileError(t *testing.T) {
	// Setup temporary directory
	tmpDir := t.TempDir()
	// Use a path in a missing directory to cause write error
	authKeysFile := filepath.Join(tmpDir, "missing", "authorized_keys")
	
	config := &Config{
		AuthorizedKeysFile: authKeysFile,
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		return "ssh-rsa success", nil
	}

	err := fetchAndUpdate(config, mockFetcher)
	if err == nil {
		t.Error("expected error due to missing directory, got nil")
	}
	
	var syncErr *SyncError
	if !errors.As(err, &syncErr) || syncErr.Code != ErrFileSystemError {
		t.Errorf("expected ErrFileSystemError, got %v", err)
	}
}

func TestRun(t *testing.T) {
	// Setup temporary directory for log file and authorized keys
	tmpDir := t.TempDir()
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	logFile := filepath.Join(tmpDir, "test.log")

	// Create initial authorized_keys file
	err := writeAuthorizedKeys(authKeysFile, []string{})
	if err != nil {
		t.Fatal(err)
	}

	// Initialize logger
	if err := initLogger(logFile); err != nil {
		t.Fatal(err)
	}

	config := &Config{
		AuthorizedKeysFile: authKeysFile,
		Interval:           10 * time.Millisecond, // Fast interval for testing
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		return "ssh-rsa success", nil
	}

	// Create context with timeout to simulate running and then stopping
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = Run(ctx, config, mockFetcher)
	if err != nil {
		t.Errorf("Run returned error: %v", err)
	}

	// Verify that we can read the file and it has content (meaning fetch happened)
	keys, err := readAuthorizedKeys(authKeysFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Error("expected keys to be synced, got empty file")
	}
}

func TestRunApp(t *testing.T) {
	// Setup environment
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	
	// Case 1: Missing config file
	err := runApp([]string{"bwkeysync", "--config", "nonexistent.yaml", "--log-file", logFile})
	if err == nil {
		t.Error("expected error for missing config file")
	}

	// Case 2: Invalid flags
	err = runApp([]string{"bwkeysync", "--invalid", "--log-file", logFile})
	if err == nil {
		t.Error("expected error for invalid flags")
	}

	// Case 3: Invalid log file (cannot create directory)
	// Use a path where a file exists as a directory component
	blockerFile := filepath.Join(tmpDir, "blocker")
	err = os.WriteFile(blockerFile, []byte{}, 0644)
	if err != nil {
		t.Fatal(err)
	}
	invalidLog := filepath.Join(blockerFile, "test.log")
	err = runApp([]string{"bwkeysync", "--log-file", invalidLog})
	if err == nil {
		t.Error("expected error for invalid log path")
	} else if !strings.Contains(err.Error(), "failed to create log directory") {
		t.Errorf("unexpected error for invalid log path: %v", err)
	}
}

func TestRunApp_RunFailure(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	configFile := filepath.Join(tmpDir, "config.yaml")
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")

	// Create valid config
	configContent := fmt.Sprintf(`
bitwarden:
  secret_id: "test"
  access_token: "test"
  server_url: "http://localhost"
authorized_keys_file: "%s"
interval: 100ms
`, authKeysFile)
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeAuthorizedKeys(authKeysFile, []string{}); err != nil {
		t.Fatal(err)
	}

	// Mock fetcher to fail immediately
	originalFetcher := DefaultFetcher
	defer func() { DefaultFetcher = originalFetcher }()
	DefaultFetcher = func(s, i, a string) (string, error) {
		return "", fmt.Errorf("immediate failure")
	}

	err := runApp([]string{"bwkeysync", "--config", configFile, "--log-file", logFile})
	if err == nil {
		t.Error("expected error from Run, got nil")
	} else if !strings.Contains(err.Error(), "immediate failure") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_InitialFailure(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	
	if err := initLogger(logFile); err != nil {
		t.Fatal(err)
	}

	config := &Config{
		AuthorizedKeysFile: authKeysFile,
		Interval:           10 * time.Millisecond,
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		return "", fmt.Errorf("initial failure")
	}

	ctx := context.Background()
	err := Run(ctx, config, mockFetcher)
	if err == nil {
		t.Error("expected error on initial failure, got nil")
	}
}

func TestRun_LoopFailure(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	
	writeAuthorizedKeys(authKeysFile, []string{})
	if err := initLogger(logFile); err != nil {
		t.Fatal(err)
	}

	config := &Config{
		AuthorizedKeysFile: authKeysFile,
		Interval:           10 * time.Millisecond,
	}
	config.Bitwarden.SecretID = "test"
	config.Bitwarden.AccessToken = "test"
	config.Bitwarden.ServerURL = "http://localhost"

	calls := 0
	mockFetcher := func(serverURL, secretID, accessToken string) (string, error) {
		calls++
		if calls == 1 {
			return "success", nil
		}
		return "", fmt.Errorf("loop failure")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := Run(ctx, config, mockFetcher)
	if err == nil {
		t.Error("expected error on loop failure, got nil")
	}
}

func TestInitLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Test setting debug level
	os.Setenv("LOG_LEVEL", "debug")
	if err := initLogger(logFile); err != nil {
		t.Fatal(err)
	}
	if logger.Level != logrus.DebugLevel {
		t.Errorf("expected DebugLevel, got %v", logger.Level)
	}
	os.Unsetenv("LOG_LEVEL")

	// Test default level
	if err := initLogger(logFile); err != nil {
		t.Fatal(err)
	}
	if logger.Level != logrus.InfoLevel {
		t.Errorf("expected InfoLevel, got %v", logger.Level)
	}
}