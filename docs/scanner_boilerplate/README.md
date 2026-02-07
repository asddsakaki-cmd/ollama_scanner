# Go Port Scanner 2026 - Production Boilerplate

Scanner TCP Connect berperforma tinggi dengan support untuk 10000+ concurrent connections, rate limiting, context cancellation, dan progress reporting.

## Features

- ✅ **10000+ Concurrent Connections** - Menggunakan semaphore pattern
- ✅ **Rate Limiting** - Token bucket implementation
- ✅ **Context Cancellation** - Proper graceful shutdown
- ✅ **Progress Reporting** - Real-time progress dengan ETA
- ✅ **Multiple Output Formats** - Plain text atau JSON
- ✅ **CIDR Support** - Scan entire networks
- ✅ **Signal Handling** - CTRL+C untuk graceful shutdown
- ✅ **Memory Efficient** - Streaming results, tidak buffering semua di memory

## Installation

```bash
cd scanner_boilerplate
go mod tidy
go build -o scanner main.go
```

## Usage

### Basic Scan

```bash
# Scan single host
./scanner -t scanme.nmap.org -p 80,443,22,8080

# Scan multiple hosts
./scanner -t "host1.com,host2.com,192.168.1.1" -p 80,443

# Scan CIDR range
./scanner -t 192.168.1.0/24 -p 22,80,443

# Scan full port range
./scanner -t target.com -p 1-65535 -c 1000
```

### Advanced Options

```bash
# High performance scan (10000 concurrent)
./scanner -t 192.168.1.0/24 -p 80,443 -c 10000 -timeout 1s

# Rate limited scan (1000 packets/sec)
./scanner -t target.com -p 1-1000 -rate 1000

# JSON output
./scanner -t target.com -p 80,443 -json

# Silent mode (hanya output hasil)
./scanner -t target.com -p 80,443 -silent

# Save to file
./scanner -t target.com -p 1-65535 -o results.json
```

### Pipe Targets dari Stdin

```bash
cat targets.txt | ./scanner -p 80,443
echo "target.com" | ./scanner -p 80,443
```

## Performance Tuning

| Network Size | Concurrency | Timeout | Rate Limit | Expected Rate |
|-------------|-------------|---------|------------|---------------|
| /24 (256) | 100-500 | 500ms | Unlimited | 500-1000/s |
| /16 (65K) | 1000-5000 | 1s | 5000/s | 2000-5000/s |
| /8 (16M) | 10000+ | 2s | 10000/s | 8000-15000/s |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         MAIN                                │
│  - Parse flags                                              │
│  - Setup context dengan signal handling                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    PORT SCANNER                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Semaphore   │  │ Rate Limiter │  │   Dialer     │      │
│  │  (Worker     │  │ (Token       │  │ (net.Dialer  │      │
│  │   Pool)      │  │  Bucket)     │  │  with ctx)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   OUTPUT HANDLER                            │
│  - Process results channel                                  │
│  - Print real-time results                                  │
│  - Save to file (optional)                                  │
│  - Print summary                                            │
└─────────────────────────────────────────────────────────────┘
```

## Code Structure

```
scanner_boilerplate/
├── main.go           # Main implementation
├── go.mod            # Dependencies
└── README.md         # Documentation
```

## Key Components

### 1. Semaphore-based Worker Pool

```go
semaphore.NewWeighted(int64(config.Concurrency))
```

Menggunakan `golang.org/x/sync/semaphore` untuk mengontrol concurrency dengan efisien.

### 2. Token Bucket Rate Limiter

```go
type TokenBucket struct {
    rate       float64    // tokens per second
    bucketSize float64    // max burst
    tokens     float64    // current tokens
    // ...
}
```

### 3. Context-aware Dialing

```go
dialer := &net.Dialer{
    Timeout:   config.Timeout,
    KeepAlive: -1,
}
conn, err := dialer.DialContext(ctx, "tcp", addr)
```

### 4. Streaming Results

```go
results := make(chan Result, bufferSize)
// Workers send to channel
// Output handler receives from channel
```

## Extending the Scanner

### Add SYN Scan Support

```go
// Implement SynScanner seperti di dokumentasi riset
func (s *Scanner) SynScan(ctx context.Context, target Target) Result {
    // Gunakan gopacket untuk raw SYN
}
```

### Add Service Detection

```go
func (s *Scanner) DetectService(target Target) string {
    conn, _ := net.Dial("tcp", target.String())
    defer conn.Close()
    
    // Send probe and read banner
    conn.Write([]byte("\r\n"))
    banner := make([]byte, 1024)
    n, _ := conn.Read(banner)
    return string(banner[:n])
}
```

### Add HTTP Title Grabbing

```go
func (s *Scanner) GetHTTPTitle(target Target) string {
    client := &http.Client{Timeout: 5 * time.Second}
    resp, _ := client.Get(fmt.Sprintf("http://%s", target.String()))
    // Parse HTML untuk title
}
```

## Comparison dengan Tools Lain

| Feature | This Scanner | naabu | nmap | masscan |
|---------|-------------|-------|------|---------|
| Pure Go | ✅ | ❌ (libpcap) | ❌ (C) | ❌ (C) |
| SYN Scan | ❌ (bisa extend) | ✅ | ✅ | ✅ |
| No Root | ✅ | ❌ (for SYN) | ❌ | ❌ |
| 10K+ Concurrency | ✅ | ✅ | ❌ | ✅ |
| Rate Limiting | ✅ | ✅ | ✅ | ✅ |
| Easy to Extend | ✅ | ✅ | ❌ | ❌ |

## License

MIT License - Free untuk personal dan commercial use.

## Disclaimer

**WARNING:** Only scan hosts you have permission to scan. Unauthorized scanning may violate laws in your jurisdiction.
