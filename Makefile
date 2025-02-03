# Makefile for Go project

BINARY_NAME=bwkeysync
INSTALL_PATH=/usr/local/bin
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: build test clean lint run install uninstall mod deps vet release release-snapshot check-goreleaser

# Build the application
build:
	@mkdir -p bin
	@CGO_ENABLED=1 CGO_LDFLAGS="-framework CoreFoundation -framework Security -framework SystemConfiguration" go build -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" -o bin/$(BINARY_NAME) .

# Run vet for static analysis
vet:
	@go vet ./...

# Run tests with coverage reporting
test:
	@go test -coverprofile=coverage.out -covermode=atomic -v ./...
	@go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	@rm -rf bin/

# Run linter
lint:
	@golangci-lint run

# Run the application
run: build
	@./bin/$(BINARY_NAME)

# Install the application
install: build
	@install -m 755 bin/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)

# Uninstall the application
uninstall:
	@rm -f $(INSTALL_PATH)/$(BINARY_NAME)

## Module dependency management targets
.PHONY: mod deps

mod:
	@go mod tidy

deps:
	@go mod download

.DEFAULT_GOAL := build
