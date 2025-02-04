# Bitwarden Key Sync 🔑

## Overview 🌐
This Go application automatically syncs a public key from Bitwarden Secrets Manager to a specified user's authorized_keys file at regular intervals.

## Requirements 📋

### Environment Variables
- `BW_SECRET_ID`: The ID of the secret containing the public key
- `BW_ACCESS_TOKEN`: Bitwarden API access token
- `BW_SERVER_URL`: Bitwarden server URL
- `BW_SSH_USER`: The user whose authorized_keys file should be updated

## Usage 🚀

### Installation
```bash
go build -o bwkeysync
```

### Running
```bash
./bwkeysync --interval 10m
```

### Options
- `--interval`: Time between key syncs (default: 10m)

## How It Works ⚙️
1. The application fetches the public key from Bitwarden Secrets Manager
2. Checks if the key exists in the user's authorized_keys file
3. If not present, appends the key to the file
4. Repeats this process at the specified interval

## Important Note
⚠️ **Warning:** The script identifies existing keys by their **comment portion** (typically the last part of the key). This means that keys with identical comments will be considered duplicates, and changing a key's comment will be treated as a new key. Modifying key material while keeping the same comment will be detected as an update.

## CI/CD Pipeline 🚀

This project uses GitHub Actions for:
- Automated testing on every push/pull request
- Building the application
- Creating and publishing Docker images

### Docker Deployment 🐳

To build and run the Docker container:

```bash
# Build the image
docker build -t bwkeysync .

# Run the container
docker run -d \
  -e BW_SECRET_ID=your_secret_id \
  -e BW_ACCESS_TOKEN=your_access_token \
  -e BW_SERVER_URL=your_server_url \
  -e BW_SSH_USER=your_ssh_user \
  --name bwkeysync \
  bwkeysync --interval 10m
```

### GitHub Actions

The CI/CD pipeline includes:
1. Unit testing
2. Building the application
3. Docker image creation and publishing

To use the Docker Hub integration, set these secrets in your GitHub repository:
- `DOCKER_HUB_USERNAME`
- `DOCKER_HUB_TOKEN`

## Graceful Shutdown 🛑
The application handles SIGINT and SIGTERM signals for clean shutdown. When terminated, it will:
1. Stop the interval ticker
2. Complete any ongoing key sync
3. Exit cleanly

## Notes 📝
- The application runs continuously in the background
- Errors are logged but don't stop the application (except for initial setup errors)
- The interval can be adjusted as needed
