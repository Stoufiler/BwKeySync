# Bitwarden SSH Key Sync

Automatically sync SSH public keys from Bitwarden Secrets Manager to `authorized_keys`.

## Features

- Configurable sync interval
- YAML configuration
- Automatic retry with exponential backoff
- Graceful shutdown handling
- Log rotation support

## Configuration

Create `config.yaml`:

```yaml
bitwarden:
  secret_id: "your_secret_id"
  access_token: "your_access_token"  
  server_url: "https://vault.bitwarden.eu"
ssh_user: "your_ssh_username" # Target user (syncs to ~user/.ssh/authorized_keys)
# authorized_keys_file: "/custom/path/authorized_keys" # Optional: Override default path
interval: 10m

# Auto-update configuration (checks GitHub releases)
auto_update:
  enabled: true
  check_interval: 24h
```

## Usage

```bash
# Default config location
./bwkeysync

# Custom config path
./bwkeysync --config /path/to/config.yaml
```

## Dependencies

- Go 1.25.5
- Bitwarden Secrets Manager API access
- gopkg.in/yaml.v3

## Running as a Service

### Systemd Service Setup

1. Create service file `/etc/systemd/system/bwkeysync.service`:
```ini
[Unit]
Description=Bitwarden SSH Key Sync Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bwkeysync --config /etc/bwkeysync/config.yaml
Restart=always
RestartSec=10
Environment="PATH=/usr/local/bin"

[Install]
WantedBy=multi-user.target
```

2. Deploy application files:
```bash
sudo mkdir -p /etc/bwkeysync
sudo cp bwkeysync /usr/local/bin/
sudo cp config.yaml /etc/bwkeysync/
sudo chmod 600 /etc/bwkeysync/config.yaml
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable bwkeysync.service
sudo systemctl start bwkeysync.service
```

4. Check the status of the service:
```bash
sudo systemctl status bwkeysync.service
```

## How It Works 
1. The application fetches the public key from Bitwarden Secrets Manager
2. Checks if the key exists in the user's authorized_keys file
3. If not present, appends the key to the file
4. Repeats this process at the specified interval

## Important Note
 ⚠️ **Warning:** The script identifies existing keys by their **comment portion** (typically the last part of the key). This means that keys with identical comments will be considered duplicates, and changing a key's comment will be treated as a new key. Modifying key material while keeping the same comment will be detected as an update.

## Graceful Shutdown 
The application handles SIGINT and SIGTERM signals for clean shutdown. When terminated, it will:
1. Stop the interval ticker
2. Complete any ongoing key sync
3. Exit cleanly

## Notes 
- The application runs continuously in the background
- Errors are logged but don't stop the application (except for initial setup errors)
- The interval can be adjusted as needed in the config file
