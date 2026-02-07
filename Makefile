# Ollama Scanner 3.0 Makefile
# Modern Go build configuration (2026)

# Project settings
BINARY_NAME := ollama-scanner
VERSION := 3.0.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go settings
GO := go
GOFLAGS := -trimpath
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
CGO_ENABLED := 1

# Directories
BUILD_DIR := build
RELEASE_DIR := releases/$(VERSION)
CMD_DIR := ./cmd/scanner

# Platforms
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Default target
.PHONY: all
all: clean build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for all platforms
.PHONY: build-all
build-all: $(PLATFORMS)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@)) \
		CGO_ENABLED=$(CGO_ENABLED) \
		$(GO) build $(GOFLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-$(word 1,$(subst /, ,$@))-$(word 2,$(subst /, ,$@))$(if $(findstring windows,$(word 1,$(subst /, ,$@))),.exe,) \
		$(CMD_DIR)
	@echo "Built: $@"

# Development build with debug info
.PHONY: dev
dev:
	@echo "Building (dev mode)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v -race ./pkg/... ./internal/...

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	$(GO) test -v ./tests/integration/...

# Run load tests
.PHONY: test-load
test-load:
	@echo "Running load tests..."
	$(GO) test -v ./tests/load/... -run TestLoad_1KTargets

# Run all tests
.PHONY: test-all
test-all: test test-integration test-load

# Test coverage
.PHONY: coverage
coverage:
	@echo "Running tests with coverage..."
	$(GO) test -coverprofile=coverage.out ./pkg/... ./internal/...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Lint code
.PHONY: lint
lint:
	@echo "Linting..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, using go vet..."; \
		$(GO) vet ./...; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# Update dependencies
.PHONY: update
update:
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(RELEASE_DIR)
	@rm -f coverage.out coverage.html

# Create release packages
.PHONY: release
release: clean build-all
	@echo "Creating release packages..."
	@mkdir -p $(RELEASE_DIR)
	
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		binary="$(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch$$ext"; \
		if [ -f "$$binary" ]; then \
			mkdir -p "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch"; \
			cp "$$binary" "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch/$(BINARY_NAME)$$ext"; \
			cp README_v3.md "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch/README.md"; \
			cp LICENSE "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch/"; \
			cp configs/config.yaml "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch/config.yaml.example"; \
			cd $(RELEASE_DIR) && tar czf "$(BINARY_NAME)-$(VERSION)-$$os-$$arch.tar.gz" "$(BINARY_NAME)-$(VERSION)-$$os-$$arch"; \
			rm -rf "$(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch"; \
			echo "Created: $(BINARY_NAME)-$(VERSION)-$$os-$$arch.tar.gz"; \
		fi; \
	done
	
	@echo "Release packages created in $(RELEASE_DIR)/"

# Docker build
.PHONY: docker
docker:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

# Docker push
.PHONY: docker-push
docker-push: docker
	@echo "Pushing Docker image..."
	docker push $(BINARY_NAME):$(VERSION)
	docker push $(BINARY_NAME):latest

# Run the scanner
.PHONY: run
run: build
	@echo "Running scanner..."
	$(BUILD_DIR)/$(BINARY_NAME) -config configs/config.yaml

# Install locally
.PHONY: install
install: build
	@echo "Installing to /usr/local/bin..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed: /usr/local/bin/$(BINARY_NAME)"

# Uninstall
.PHONY: uninstall
uninstall:
	@echo "Uninstalling..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled"

# Show version
.PHONY: version
version:
	@echo "$(VERSION)"

# Show help
.PHONY: help
help:
	@echo "Ollama Scanner $(VERSION) - Available targets:"
	@echo ""
	@echo "  make build           - Build for current platform"
	@echo "  make build-all       - Build for all platforms"
	@echo "  make dev             - Build for development (with debug info)"
	@echo "  make test            - Run unit tests"
	@echo "  make test-integration- Run integration tests"
	@echo "  make test-load       - Run load tests"
	@echo "  make test-all        - Run all tests"
	@echo "  make coverage        - Run tests with coverage report"
	@echo "  make lint            - Run linter"
	@echo "  make fmt             - Format code"
	@echo "  make deps            - Download dependencies"
	@echo "  make update          - Update dependencies"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make release         - Create release packages"
	@echo "  make docker          - Build Docker image"
	@echo "  make docker-push     - Push Docker image"
	@echo "  make install         - Install to /usr/local/bin"
	@echo "  make uninstall       - Uninstall from /usr/local/bin"
	@echo "  make version         - Show version"
	@echo "  make help            - Show this help"
