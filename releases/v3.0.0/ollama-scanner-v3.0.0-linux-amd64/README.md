# Ollama Scanner 3.0

Modern Go-based Ollama security scanner with checkpoint/resume capability.

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/aspnmy/ollama_scanner)
[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- 🔍 **Native Go TCP Scanner** - No external dependencies (zmap/masscan optional)
- 🛡️ **Security Audit** - Detect tool-calling, MCP, uncensored models (based on 2026 research)
- 💾 **Checkpoint/Resume** - Never lose scan progress, resume interrupted scans
- 📊 **Risk Scoring** - 1-10 risk score based on SentinelOne/Censys research
- 🚀 **High Performance** - 30K+ targets/sec with low memory usage
- 🐳 **Docker Support** - Ready-to-use Docker image

## Quick Start

### Binary Installation

```bash
# Download latest release
wget https://github.com/aspnmy/ollama_scanner/releases/download/v3.0.0/ollama-scanner-linux-amd64
chmod +x ollama-scanner-linux-amd64
mv ollama-scanner-linux-amd64 /usr/local/bin/ollama-scanner

# Verify installation
ollama-scanner --version
```

### Docker Installation

```bash
# Clone repository
git clone https://github.com/aspnmy/ollama_scanner.git
cd ollama_scanner

# Build and run with Docker Compose
docker-compose up -d

# Or run directly
docker run --rm -it \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/checkpoints:/app/checkpoints \
  ollama-scanner:3.0.0 \
  -targets "10.0.0.0/24" -v
```

## Usage

### Basic Scanning

```bash
# Scan a network
ollama-scanner -targets "192.168.1.0/24"

# Scan with custom ports
ollama-scanner -targets "10.0.0.0/16" -ports "11434,11435,8080"

# Fast scan with high concurrency
ollama-scanner -targets "172.16.0.0/12" -workers 5000 -rate 50000
```

### Security Audit

```bash
# Full security audit (default)
ollama-scanner -targets "192.168.1.0/24" -v

# Port scan only (faster)
ollama-scanner -targets "192.168.1.0/24" -no-detect

# Skip security audit
ollama-scanner -targets "192.168.1.0/24" -no-security
```

### Checkpoint/Resume

```bash
# Start a long scan (auto-checkpoint every 30 seconds)
ollama-scanner -targets "0.0.0.0/0" -max-targets 100000000

# List available checkpoints
ollama-scanner -list-checkpoints

# Resume interrupted scan
ollama-scanner -resume scan_abc123

# Delete old checkpoint
ollama-scanner -delete-checkpoint scan_abc123
```

### Output Formats

```bash
# JSON Lines (default)
ollama-scanner -targets "10.0.0.0/24" -output jsonl

# Console output only
ollama-scanner -targets "10.0.0.0/24" -output console

# Multiple formats
ollama-scanner -targets "10.0.0.0/24" -output "jsonl,console"
```

## Command Line Options

```
-targets string
    Comma-separated CIDRs (e.g., 10.0.0.0/24,192.168.1.0/24)

-ports string
    Comma-separated ports to scan (default "11434")

-engine string
    Scanner engine: native, zmap, masscan (default "native")

-rate int
    Max requests per second (default 5000)

-workers int
    Number of concurrent workers (default 1000)

-timeout duration
    Connection timeout (default 3s)

-output string
    Output format: jsonl, csv, console (default "jsonl")

-resume string
    Resume scan from checkpoint (scan ID)

-list-checkpoints
    List available checkpoints

-no-checkpoint
    Disable checkpointing

-no-detect
    Skip Ollama detection (port scan only)

-no-security
    Skip security audit

-max-targets int
    Maximum targets to scan (safety limit) (default 10000000)
```

## Security Audit Checks

Based on research of 175,000 publicly exposed Ollama instances (SentinelOne/Censys, Jan 2026):

| Check | Severity | Description |
|-------|----------|-------------|
| **Authentication** | Critical | Detect if endpoints require authentication |
| **Tool-Calling** | Critical | 48% of exposed hosts have tool-calling enabled |
| **MCP Support** | High | Model Context Protocol for K8s/cloud access |
| **Uncensored Models** | High | Models without safety guardrails |
| **CVE Detection** | Critical | Known vulnerabilities (CVE-2024-37032, etc.) |
| **CORS Misconfig** | Medium | Wildcard origins, credentials allowed |

## Risk Scoring

Scans are scored 1-10 based on security posture:

| Score | Rating | Description |
|-------|--------|-------------|
| 9-10 | **CRITICAL** | Immediate action required - highly vulnerable |
| 7-8 | **HIGH** | Severe risk - tool-calling or management exposed |
| 4-6 | **MEDIUM** | Moderate risk - multiple issues present |
| 2-3 | **LOW** | Low risk - some exposure but limited impact |
| 1 | **MINIMAL** | Good security posture |

## Output Format (JSONL)

```json
{
  "target": {
    "IP": "192.168.1.10",
    "Port": 11434
  },
  "open": true,
  "is_ollama": true,
  "version": "0.4.0",
  "models": [
    {"name": "llama3.1:8b", "size": 4920000000}
  ],
  "security_report": {
    "risk_score": 8,
    "risk_rating": "HIGH",
    "auth_enabled": false,
    "tool_calling_enabled": true,
    "tool_calling_models": ["llama3.1:8b"],
    "mcp_enabled": false,
    "vulnerabilities": []
  }
}
```

## Performance

Tested on AMD Ryzen 5 3600, 16GB RAM:

| Targets | Duration | Rate | Memory |
|---------|----------|------|--------|
| 1,000 | 29ms | 34,480/sec | 0.07 KB/target |
| 10,000 | 119ms | 41,959/sec | 0.01 KB/target |
| 100,000 | ~2s | 50,000/sec | < 10 MB total |

## Building from Source

```bash
# Clone repository
git clone https://github.com/aspnmy/ollama_scanner.git
cd ollama_scanner

# Build
go build -o ollama-scanner ./cmd/scanner

# Run tests
go test ./...

# Build for all platforms
make build-all
```

## Development

```bash
# Run unit tests
go test ./pkg/cidr/... ./pkg/ratelimit/... -v

# Run integration tests
go test ./tests/integration/... -v

# Run load tests
go test ./tests/load/... -run TestLoad_10KTargets -v

# Run benchmarks
go test ./tests/load/... -bench=BenchmarkLoad -benchmem
```

## Docker Usage

```bash
# Build image
docker build -t ollama-scanner:3.0.0 .

# Scan with Docker
docker run --rm -it \
  --network host \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/checkpoints:/app/checkpoints \
  ollama-scanner:3.0.0 \
  -targets "192.168.1.0/24" -v

# Using Docker Compose
docker-compose up -d
docker-compose logs -f scanner
```

## Architecture

```
cmd/scanner/         # Main entry point
internal/
├── app/            # Application orchestrator
├── scanner/        # TCP scanner engines
├── detector/       # Ollama detection & security audit
├── checkpoint/     # Resume capability
├── output/         # Output formatters
└── models/         # Data models
pkg/
├── cidr/           # CIDR parsing
├── ratelimit/      # Rate limiting
└── logger/         # Structured logging
tests/
├── integration/    # Integration tests
└── load/           # Load tests
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Security audit based on research by SentinelOne, Censys, and Pillar Security (Jan 2026)
- 175,000 exposed Ollama instances analyzed for threat modeling

## Disclaimer

This tool is intended for authorized security scanning only. Always obtain permission before scanning networks you don't own.
