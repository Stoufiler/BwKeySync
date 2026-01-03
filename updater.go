package main

import (
	"os"
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// version is injected by ldflags
var version = "dev"

var (
	detectLatest = selfupdate.DetectLatest
	updateTo     = selfupdate.UpdateTo
	osExit       = os.Exit
	osExecutable = os.Executable
)

// startUpdateScheduler starts the auto-update check loop.
// It returns a stop function to cancel the scheduler (useful for testing or graceful shutdown).
func startUpdateScheduler(config *Config) func() {
	if !config.AutoUpdate.Enabled {
		logger.Info("Auto-update disabled")
		return func() {}
	}

	interval := config.AutoUpdate.CheckInterval
	if interval == 0 {
		interval = 24 * time.Hour
	}

	logger.Infof("Starting auto-update scheduler. Interval: %s", interval)

	// Create a channel to signal stop
	stopChan := make(chan struct{})

	// Run check immediately in background
	go func() {
		checkForUpdates()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				checkForUpdates()
			case <-stopChan:
				return
			}
		}
	}()

	return func() {
		close(stopChan)
	}
}

func checkForUpdates() {
	logger.Info("Checking for updates...")
	latest, found, err := detectLatest("Stoufiler/BwKeySync")
	if err != nil {
		logger.Errorf("Update check failed: %v", err)
		return
	}

	if !found {
		logger.Info("No updates found")
		return
	}

	currentVersion, err := semver.ParseTolerant(version)
	if err != nil {
		logger.Warnf("Could not parse current version '%s': %v. Skipping update check.", version, err)
		return
	}

	if latest.Version.GT(currentVersion) {
		logger.Infof("New version %s available (current: %s). Updating...", latest.Version, currentVersion)
		
		exe, err := osExecutable()
		if err != nil {
			logger.Errorf("Could not locate executable path: %v", err)
			return
		}

		if err := updateTo(latest.AssetURL, exe); err != nil {
			logger.Errorf("Update failed: %v", err)
			return
		}
		logger.Infof("Successfully updated to %s. Restarting...", latest.Version)
		osExit(0) 
	} else {
		logger.Info("Already running latest version")
	}
}
