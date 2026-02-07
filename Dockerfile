# Dockerfile for Ollama Scanner 3.0
# Multi-stage build for minimal image size

# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.version=3.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o ollama-scanner ./cmd/scanner

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

# Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ollama-scanner /usr/local/bin/ollama-scanner

# Create directories for data
RUN mkdir -p /app/results /app/checkpoints && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Default entrypoint
ENTRYPOINT ["ollama-scanner"]

# Default command (show help)
CMD ["--help"]
