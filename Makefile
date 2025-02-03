# Generic Makefile for Go applications
BINARY_NAME ?= BwKeySync
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DIR ?= bin
DIST_DIR ?= dist
RELEASE_DIR ?= release

.PHONY: all build clean test lint vet mod deps run install uninstall help

all: build

## Build:
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -v \
		-ldflags "-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" \
		-o $(BUILD_DIR)/$(BINARY_NAME) .

## Cross-compilation targets:
# Build targets
linux-amd64:
	@mkdir -p $(DIST_DIR)/linux/amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags "-w -s -X main.version=$(VERSION)" \
		-o $(DIST_DIR)/linux/amd64/$(BINARY_NAME) .

linux-arm64:
	@mkdir -p $(DIST_DIR)/linux/arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags "-w -s -X main.version=$(VERSION)" \
		-o $(DIST_DIR)/linux/arm64/$(BINARY_NAME) .

darwin-amd64:
	@mkdir -p $(DIST_DIR)/darwin/amd64
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 CC=clang go build \
		-ldflags "-X main.version=$(VERSION) -extldflags '-lm -framework CoreFoundation -framework Security -framework SystemConfiguration'" \
		-o $(DIST_DIR)/darwin/amd64/$(BINARY_NAME) .

darwin-arm64:
	@mkdir -p $(DIST_DIR)/darwin/arm64
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 CC=clang go build \
		-ldflags "-X main.version=$(VERSION) -extldflags '-lm -framework CoreFoundation -framework Security -framework SystemConfiguration'" \
		-o $(DIST_DIR)/darwin/arm64/$(BINARY_NAME) .

# Meta targets
linux: linux-amd64 linux-arm64
darwin: darwin-amd64 darwin-arm64
all: linux darwin

# Packaging (now with proper dependencies)
package: linux darwin
	@mkdir -p $(RELEASE_DIR)
	tar -czvf $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(DIST_DIR)/linux/amd64 $(BINARY_NAME)
	tar -czvf $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz -C $(DIST_DIR)/linux/arm64 $(BINARY_NAME)
	tar -czvf $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(DIST_DIR)/darwin/amd64 $(BINARY_NAME)
	tar -czvf $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz -C $(DIST_DIR)/darwin/arm64 $(BINARY_NAME)
	md5sum $(RELEASE_DIR)/*.tar.gz > $(RELEASE_DIR)/checksums.md5
## Maintenance:
clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(RELEASE_DIR)

test:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run

vet:
	go vet ./...

mod:
	go mod tidy

deps:
	go mod download

## Installation:
install: build
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)

## Help:
help:
	@echo "Available targets:"
	@echo "  build       - Build application"
	@echo "  linux-*     - Cross-compile for Linux architectures"
	@echo "  darwin-*    - Cross-compile for macOS architectures"
	@echo "  package     - Create release packages"
	@echo "  test        - Run tests with coverage"
	@echo "  lint        - Run linter"
	@echo "  vet         - Run vet"
	@echo "  mod         - Tidy module dependencies"
	@echo "  install     - Install to /usr/local/bin"
	@echo "  uninstall   - Remove from /usr/local/bin"
	@echo "  clean       - Remove build artifacts"

.DEFAULT_GOAL := help