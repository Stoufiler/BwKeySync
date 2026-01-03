package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

func TestCheckForUpdates(t *testing.T) {
	// Backup original functions
	origDetect := detectLatest
	origUpdate := updateTo
	origExit := osExit
	origExecutable := osExecutable
	origVersion := version
	defer func() {
		detectLatest = origDetect
		updateTo = origUpdate
		osExit = origExit
		osExecutable = origExecutable
		version = origVersion
	}()

	tests := []struct {
		name           string
		currentVer     string
		latestVer      string
		found          bool
		detectErr      error
		updateErr      error
		expectUpdate   bool
		expectExit     bool
		expectErrLog   bool
	}{
		{
			name:         "no update found",
			currentVer:   "1.0.0",
			found:        false,
			expectUpdate: false,
		},
		{
			name:         "already on latest",
			currentVer:   "1.1.0",
			latestVer:    "1.1.0",
			found:        true,
			expectUpdate: false,
		},
		{
			name:         "new version available - success",
			currentVer:   "1.0.0",
			latestVer:    "1.1.0",
			found:        true,
			expectUpdate: true,
			expectExit:   true,
		},
		{
			name:         "detect error",
			currentVer:   "1.0.0",
			detectErr:    fmt.Errorf("api error"),
			expectUpdate: false,
		},
		{
			name:         "update error",
			currentVer:   "1.0.0",
			latestVer:    "1.1.0",
			found:        true,
			updateErr:    fmt.Errorf("download failed"),
			expectUpdate: true,
			expectExit:   false,
		},
		{
			name:         "invalid current version",
			currentVer:   "invalid",
			latestVer:    "1.1.0",
			found:        true,
			expectUpdate: false,
		},
		{
			name:         "executable path error",
			currentVer:   "1.0.0",
			latestVer:    "1.1.0",
			found:        true,
			expectUpdate: false, // Should fail before updateTo
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.currentVer
			updateCalled := false
			exitCalled := false

			detectLatest = func(repo string) (*selfupdate.Release, bool, error) {
				if tt.detectErr != nil {
					return nil, false, tt.detectErr
				}
				if !tt.found {
					return nil, false, nil
				}
				v, _ := semver.Parse(tt.latestVer)
				return &selfupdate.Release{
					Version:  v,
					AssetURL: "http://example.com/asset",
				}, true, nil
			}

			updateTo = func(url string, exe string) error {
				updateCalled = true
				return tt.updateErr
			}

			osExit = func(code int) {
				exitCalled = true
			}
			
			osExecutable = func() (string, error) {
				if tt.name == "executable path error" {
					return "", fmt.Errorf("exe error")
				}
				return "/path/to/exe", nil
			}

			checkForUpdates()

			if updateCalled != tt.expectUpdate {
				t.Errorf("expected updateCalled to be %v, got %v", tt.expectUpdate, updateCalled)
			}
			if exitCalled != tt.expectExit {
				t.Errorf("expected exitCalled to be %v, got %v", tt.expectExit, exitCalled)
			}
		})
	}
}

func TestStartUpdateScheduler_Disabled(t *testing.T) {
	config := &Config{}
	config.AutoUpdate.Enabled = false

	stop := startUpdateScheduler(config)
	stop()
}

func TestStartUpdateScheduler_Enabled(t *testing.T) {
	config := &Config{}
	config.AutoUpdate.Enabled = true
	config.AutoUpdate.CheckInterval = 10 * time.Millisecond

	// Mock detectLatest to signal when called
	called := make(chan bool, 1)
	origDetect := detectLatest
	defer func() { detectLatest = origDetect }()
	
	detectLatest = func(repo string) (*selfupdate.Release, bool, error) {
		select {
		case called <- true:
		default:
		}
		return nil, false, nil
	}

	stop := startUpdateScheduler(config)
	defer stop()

	select {
	case <-called:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("timed out waiting for update check")
	}
}
