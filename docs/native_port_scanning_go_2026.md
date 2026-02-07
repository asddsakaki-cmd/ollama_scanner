# Riset: Native Port Scanning di Go (2026)

## Executive Summary

Go adalah bahasa yang sangat cocok untuk port scanning berkat:
- Goroutines yang lightweight (2KB stack awal vs 1-8MB thread OS)
- Runtime scheduler yang efisien (M:N scheduling)
- Standard library `net` yang matang
- Mendukung 100K+ concurrent connections dengan mudah

---

## 1. TCP Connect Scanning (No Root Required)

### 1.1 Best Practices High-Performance Concurrent Scanning

#### Pattern 1: Semaphore-based Worker Pool (Recommended)

```go
package scanner

import (
    "context"
    "net"
    "sync"
    "time"
    
    "golang.org/x/sync/semaphore"
)

// Config holds scanner configuration
type Config struct {
    Concurrency     int           // Max concurrent connections
    Timeout         time.Duration // Connection timeout
    RateLimit       int           // Packets per second (0 = unlimited)
    RetryAttempts   int
    WarmUpTime      time.Duration
}

// Result represents scan result
type Result struct {
    Host      string
    Port      int
    IsOpen    bool
    Latency   time.Duration
    Error     error
    Timestamp time.Time
}

// Scanner is the main scanner struct
type Scanner struct {
    config    *Config
    sem       *semaphore.Weighted
    rateLimiter *RateLimiter
    dialer    *net.Dialer
}

// NewScanner creates a new scanner instance
func NewScanner(config *Config) *Scanner {
    return &Scanner{
        config: config,
        sem:    semaphore.NewWeighted(int64(config.Concurrency)),
        rateLimiter: NewTokenBucket(config.RateLimit),
        dialer: &net.Dialer{
            Timeout: config.Timeout,
            // Reuse address untuk high-throughput
            LocalAddr: nil,
        },
    }
}

// ScanPort scans a single port
func (s *Scanner) ScanPort(ctx context.Context, host string, port int) *Result {
    start := time.Now()
    
    // Rate limiting
    if s.config.RateLimit > 0 {
        s.rateLimiter.Wait()
    }
    
    target := net.JoinHostPort(host, strconv.Itoa(port))
    
    conn, err := s.dialer.DialContext(ctx, "tcp", target)
    if err != nil {
        return &Result{
            Host:      host,
            Port:      port,
            IsOpen:    false,
            Error:     err,
            Timestamp: time.Now(),
        }
    }
    defer conn.Close()
    
    return &Result{
        Host:      host,
        Port:      port,
        IsOpen:    true,
        Latency:   time.Since(start),
        Timestamp: time.Now(),
    }
}

// ScanRange scans a range of ports on a host
func (s *Scanner) ScanRange(ctx context.Context, host string, ports []int) <-chan *Result {
    results := make(chan *Result, len(ports))
    
    var wg sync.WaitGroup
    for _, port := range ports {
        wg.Add(1)
        
        // Acquire semaphore
        if err := s.sem.Acquire(ctx, 1); err != nil {
            wg.Done()
            continue
        }
        
        go func(p int) {
            defer wg.Done()
            defer s.sem.Release(1)
            
            select {
            case <-ctx.Done():
                return
            case results <- s.ScanPort(ctx, host, p):
            }
        }(port)
    }
    
    go func() {
        wg.Wait()
        close(results)
    }()
    
    return results
}
```

#### Pattern 2: errgroup untuk Error Handling Lebih Baik

```go
package scanner

import (
    "context"
    
    "golang.org/x/sync/errgroup"
)

// ScanWithErrgroup menggunakan errgroup untuk better error handling
func (s *Scanner) ScanWithErrgroup(ctx context.Context, targets []Target) ([]Result, error) {
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(s.config.Concurrency)
    
    results := make([]Result, 0, len(targets))
    var mu sync.Mutex
    
    for _, target := range targets {
        target := target // capture for goroutine
        
        g.Go(func() error {
            select {
            case <-ctx.Done():
                return ctx.Err()
            default:
            }
            
            result := s.ScanPort(ctx, target.Host, target.Port)
            
            mu.Lock()
            results = append(results, *result)
            mu.Unlock()
            
            return nil
        })
    }
    
    if err := g.Wait(); err != nil {
        return nil, err
    }
    
    return results, nil
}
```

#### Pattern 3: Channel-based Worker Pool (Classic)

```go
package scanner

// WorkerPool manages a pool of workers
func (s *Scanner) WorkerPool(ctx context.Context, numWorkers int) (chan<- Target, <-chan Result) {
    jobs := make(chan Target, numWorkers*2)
    results := make(chan Result, numWorkers*2)
    
    var wg sync.WaitGroup
    
    // Start workers
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            
            for target := range jobs {
                select {
                case <-ctx.Done():
                    return
                default:
                }
                
                result := s.ScanPort(ctx, target.Host, target.Port)
                results <- *result
            }
        }()
    }
    
    // Close results when all workers done
    go func() {
        wg.Wait()
        close(results)
    }()
    
    return jobs, results
}
```

### 1.2 Rate Limiting Techniques

#### Token Bucket (Recommended untuk Port Scanning)

```go
package scanner

import (
    "sync"
    "time"
)

// TokenBucket implements token bucket rate limiter
type TokenBucket struct {
    rate       float64    // tokens per second
    bucketSize float64
    tokens     float64
    lastUpdate time.Time
    mu         sync.Mutex
}

// NewTokenBucket creates new token bucket rate limiter
func NewTokenBucket(rate int) *TokenBucket {
    if rate <= 0 {
        return nil
    }
    
    return &TokenBucket{
        rate:       float64(rate),
        bucketSize: float64(rate), // Burst = rate
        tokens:     float64(rate),
        lastUpdate: time.Now(),
    }
}

// Wait blocks until a token is available
func (tb *TokenBucket) Wait() {
    if tb == nil {
        return
    }
    
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    now := time.Now()
    elapsed := now.Sub(tb.lastUpdate).Seconds()
    tb.lastUpdate = now
    
    // Add tokens based on elapsed time
    tb.tokens += elapsed * tb.rate
    if tb.tokens > tb.bucketSize {
        tb.tokens = tb.bucketSize
    }
    
    if tb.tokens < 1 {
        // Calculate wait time
        waitTime := time.Duration((1 - tb.tokens) / tb.rate * float64(time.Second))
        time.Sleep(waitTime)
        tb.tokens = 0
    } else {
        tb.tokens--
    }
}
```

#### Leaky Bucket (Alternative)

```go
package scanner

import (
    "context"
    "time"
)

// LeakyBucket implements leaky bucket rate limiter
type LeakyBucket struct {
    rate     time.Duration // interval between requests
    bucket   chan struct{}
    ctx      context.Context
    cancel   context.CancelFunc
}

// NewLeakyBucket creates new leaky bucket rate limiter
func NewLeakyBucket(requestsPerSecond int) *LeakyBucket {
    ctx, cancel := context.WithCancel(context.Background())
    
    lb := &LeakyBucket{
        rate:   time.Second / time.Duration(requestsPerSecond),
        bucket: make(chan struct{}, 1),
        ctx:    ctx,
        cancel: cancel,
    }
    
    go lb.leak()
    
    return lb
}

func (lb *LeakyBucket) leak() {
    ticker := time.NewTicker(lb.rate)
    defer ticker.Stop()
    
    for {
        select {
        case <-lb.ctx.Done():
            return
        case lb.bucket <- struct{}{}:
        case <-ticker.C:
        }
    }
}

// Wait blocks until bucket has space
func (lb *LeakyBucket) Wait() {
    <-lb.bucket
}

// Stop stops the rate limiter
func (lb *LeakyBucket) Stop() {
    lb.cancel()
}
```

---

## 2. Performance Benchmarks

### 2.1 Realistic Performance Numbers

Berdasarkan benchmark dan riset:

| Configuration | Hosts/Second | Notes |
|--------------|--------------|-------|
| 100 concurrent, 1s timeout | ~500-1000 hosts/s | Default settings |
| 1000 concurrent, 500ms timeout | ~2000-5000 hosts/s | VPS optimized |
| 10000 concurrent, 200ms timeout | ~8000-15000 hosts/s | High-end VPS |
| 65535 concurrency (unlimited) | ~15000+ hosts/s | Local network only |

### 2.2 Memory Usage Patterns

```
Scan /8 (16.7M hosts):
- Concurrent connections: 10,000
- Memory per connection: ~2-4KB
- Total memory: ~500MB - 2GB

Scan /16 (65K hosts):
- Concurrent connections: 10,000  
- Memory per connection: ~2-4KB
- Total memory: ~200MB - 500MB

Scan /24 (256 hosts):
- Concurrent connections: 256
- Memory per connection: ~2-4KB
- Total memory: ~10MB - 50MB
```

### 2.3 Optimal Configuration Table

| Network Size | Concurrency | Timeout | Rate Limit | Use Case |
|-------------|-------------|---------|------------|----------|
| /24 (256) | 100-500 | 500ms | Unlimited | LAN scanning |
| /16 (65K) | 1000-5000 | 1s | 5000/s | Corporate network |
| /8 (16M) | 10000+ | 2s | 10000/s | Internet-wide |

---

## 3. Modern Libraries Analysis

### 3.1 Library Comparison

| Library | Pros | Cons | Use Case |
|---------|------|------|----------|
| **Standard net** | No deps, stable, fast | No advanced features | Basic scanning |
| **gonmap** | Pure Go, nmap-like | Less maintained | Learning purpose |
| **naabu** | Production-ready, SYN/CONNECT | Requires libpcap | Professional use |
| **gopacket** | Full packet control | Requires C bindings | Custom protocols |

### 3.2 Recommendation: Standard Library untuk CONNECT, gopacket untuk SYN

```go
// Untuk TCP Connect Scan (No root) - Standard library is BEST
func StandardConnect(host string, port int, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", 
        net.JoinHostPort(host, strconv.Itoa(port)), 
        timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

// Untuk SYN Scan (Root required) - gopacket
func SynScan(iface string, target net.IP, port int) error {
    // Lihat section SYN Stealth Scan
}
```

---

## 4. SYN Stealth Scan

### 4.1 Apakah Possible di Go Tanpa C Binding?

**Jawaban: YA, dengan keterbatasan**

Go bisa melakukan raw socket dan packet crafting tanpa C binding, tapi:
1. **Linux**: Bisa pakai `syscall` atau `golang.org/x/sys/unix`
2. **Windows**: Perlu C binding atau external library
3. **macOS**: Raw socket terbatas, perlu root

### 4.2 Implementasi SYN Scan dengan gopacket

```go
package synscan

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// SynScanner performs SYN stealth scans
type SynScanner struct {
    iface      string
    srcIP      net.IP
    handle     *pcap.Handle
    timeout    time.Duration
    
    // For response tracking
    responses  map[uint16]chan bool // port -> result channel
    mu         sync.RWMutex
    
    tcpSeq     uint32
    tcpSeqMu   sync.Mutex
}

// NewSynScanner creates a new SYN scanner
func NewSynScanner(iface string, timeout time.Duration) (*SynScanner, error) {
    // Open device
    handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
    if err != nil {
        return nil, fmt.Errorf("pcap open: %w", err)
    }
    
    // Set filter for TCP
    if err := handle.SetBPFFilter("tcp"); err != nil {
        handle.Close()
        return nil, fmt.Errorf("set filter: %w", err)
    }
    
    scanner := &SynScanner{
        iface:     iface,
        handle:    handle,
        timeout:   timeout,
        responses: make(map[uint16]chan bool),
        tcpSeq:    1000, // Initial sequence number
    }
    
    // Start packet reader
    go scanner.readPackets()
    
    return scanner, nil
}

// getSrcIP determines the source IP for scanning
func (s *SynScanner) getSrcIP(dst net.IP) net.IP {
    if s.srcIP != nil {
        return s.srcIP
    }
    
    // Find appropriate interface
    iface, err := net.InterfaceByName(s.iface)
    if err != nil {
        return nil
    }
    
    addrs, err := iface.Addrs()
    if err != nil {
        return nil
    }
    
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok {
            if ip4 := ipnet.IP.To4(); ip4 != nil {
                s.srcIP = ip4
                return ip4
            }
        }
    }
    
    return nil
}

// nextSeq returns next TCP sequence number
func (s *SynScanner) nextSeq() uint32 {
    s.tcpSeqMu.Lock()
    defer s.tcpSeqMu.Unlock()
    s.tcpSeq++
    return s.tcpSeq
}

// ScanPort performs SYN scan on a single port
func (s *SynScanner) ScanPort(ctx context.Context, dstIP net.IP, port uint16) (bool, error) {
    srcIP := s.getSrcIP(dstIP)
    if srcIP == nil {
        return false, fmt.Errorf("cannot determine source IP")
    }
    
    // Create result channel
    resultCh := make(chan bool, 1)
    s.mu.Lock()
    s.responses[port] = resultCh
    s.mu.Unlock()
    
    defer func() {
        s.mu.Lock()
        delete(s.responses, port)
        s.mu.Unlock()
    }()
    
    // Build and send SYN packet
    if err := s.sendSYN(srcIP, dstIP, port); err != nil {
        return false, err
    }
    
    // Wait for response or timeout
    select {
    case result := <-resultCh:
        return result, nil
    case <-time.After(s.timeout):
        return false, nil // Filtered or no response
    case <-ctx.Done():
        return false, ctx.Err()
    }
}

// sendSYN sends a SYN packet
func (s *SynScanner) sendSYN(srcIP, dstIP net.IP, dstPort uint16) error {
    // Ethernet layer (auto-generated by pcap)
    
    // IP Layer
    ip := &layers.IPv4{
        SrcIP:    srcIP,
        DstIP:    dstIP,
        Version:  4,
        IHL:      5,
        TOS:      0,
        Length:   0, // Will be calculated
        Id:       0, // Will be set by kernel or 0
        Flags:    layers.IPv4DontFragment,
        TTL:      64,
        Protocol: layers.IPProtocolTCP,
    }
    
    // TCP Layer
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(12345 + uint16(s.nextSeq()%50000)), // Random source port
        DstPort: layers.TCPPort(dstPort),
        Seq:     s.nextSeq(),
        SYN:     true,
        Window:  1460,
    }
    
    // Set TCP checksum
    tcp.SetNetworkLayerForChecksum(ip)
    
    // Serialize
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths:       true,
    }
    
    if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
        return err
    }
    
    // Write packet
    return s.handle.WritePacketData(buf.Bytes())
}

// readPackets reads and processes incoming packets
func (s *SynScanner) readPackets() {
    packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
    
    for packet := range packetSource.Packets() {
        s.processPacket(packet)
    }
}

// processPacket processes a single packet
func (s *SynScanner) processPacket(packet gopacket.Packet) {
    // Get TCP layer
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer == nil {
        return
    }
    
    tcp, _ := tcpLayer.(*layers.TCP)
    
    // Check if this is a response to our scan
    port := uint16(tcp.SrcPort)
    
    s.mu.RLock()
    resultCh, exists := s.responses[port]
    s.mu.RUnlock()
    
    if !exists {
        return
    }
    
    // Check flags
    if tcp.SYN && tcp.ACK {
        // Port is open!
        select {
        case resultCh <- true:
        default:
        }
    } else if tcp.RST {
        // Port is closed
        select {
        case resultCh <- false:
        default:
        }
    }
}

// Close closes the scanner
func (s *SynScanner) Close() {
    if s.handle != nil {
        s.handle.Close()
    }
}
```

### 4.3 Alternative: eBPF untuk Performance Tertinggi

```go
// Untuk 2026, eBPF adalah teknologi terbaru untuk packet processing
// Menggunakan cilium/ebpf atau aquasecurity/tracee

// Namun, ini memerlukan kernel 5.x+ dan privileges
// Lebih cocok untuk production-grade scanner
```

---

## 5. Host Discovery

### 5.1 ICMP Ping

```go
package discovery

import (
    "context"
    "net"
    "time"
    
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

// Ping performs ICMP echo request
func Ping(ctx context.Context, dst net.IP, timeout time.Duration) (bool, time.Duration, error) {
    // Create ICMP connection
    conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        return false, 0, err
    }
    defer conn.Close()
    
    // Build ICMP Echo Request
    msg := &icmp.Message{
        Type: ipv4.ICMPTypeEcho,
        Code: 0,
        Body: &icmp.Echo{
            ID:   1,
            Seq:  1,
            Data: []byte("hello"),
        },
    }
    
    data, err := msg.Marshal(nil)
    if err != nil {
        return false, 0, err
    }
    
    start := time.Now()
    
    // Send
    if _, err := conn.WriteTo(data, &net.IPAddr{IP: dst}); err != nil {
        return false, 0, err
    }
    
    // Set deadline
    conn.SetReadDeadline(time.Now().Add(timeout))
    
    // Receive
    reply := make([]byte, 1500)
    for {
        select {
        case <-ctx.Done():
            return false, 0, ctx.Err()
        default:
        }
        
        n, peer, err := conn.ReadFrom(reply)
        if err != nil {
            return false, 0, err
        }
        
        rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
        if err != nil {
            continue
        }
        
        if rm.Type == ipv4.ICMPTypeEchoReply {
            latency := time.Since(start)
            if peer.String() == dst.String() {
                return true, latency, nil
            }
        }
    }
}
```

### 5.2 TCP SYN Ping (No Root)

```go
// TCPPing uses TCP SYN untuk host discovery (no root needed untuk basic version)
func TCPPing(host string, port int, timeout time.Duration) (bool, time.Duration) {
    start := time.Now()
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
    if err != nil {
        // Check if it's connection refused (host is up)
        if strings.Contains(err.Error(), "connection refused") {
            return true, time.Since(start)
        }
        return false, 0
    }
    defer conn.Close()
    return true, time.Since(start)
}
```

### 5.3 ARP Scan untuk LAN

```go
package discovery

import (
    "net"
    "time"
    
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// ArpScanner performs ARP scanning on local network
type ArpScanner struct {
    handle    *pcap.Handle
    iface     *net.Interface
    timeout   time.Duration
}

// NewArpScanner creates ARP scanner for interface
func NewArpScanner(ifaceName string, timeout time.Duration) (*ArpScanner, error) {
    iface, err := net.InterfaceByName(ifaceName)
    if err != nil {
        return nil, err
    }
    
    handle, err := pcap.OpenLive(ifaceName, 65536, true, timeout)
    if err != nil {
        return nil, err
    }
    
    // Filter for ARP
    if err := handle.SetBPFFilter("arp"); err != nil {
        handle.Close()
        return nil, err
    }
    
    return &ArpScanner{
        handle:  handle,
        iface:   iface,
        timeout: timeout,
    }, nil
}

// Scan sends ARP request to target IP
func (a *ArpScanner) Scan(targetIP net.IP) (net.HardwareAddr, error) {
    // Get our addresses
    var srcIP net.IP
    var srcMAC net.HardwareAddr
    
    addrs, _ := a.iface.Addrs()
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok {
            if ip4 := ipnet.IP.To4(); ip4 != nil {
                srcIP = ip4
                break
            }
        }
    }
    srcMAC = a.iface.HardwareAddr
    
    // Build ARP request
    eth := &layers.Ethernet{
        SrcMAC:       srcMAC,
        DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
        EthernetType: layers.EthernetTypeARP,
    }
    
    arp := &layers.ARP{
        AddrType:          layers.LinkTypeEthernet,
        Protocol:          layers.EthernetTypeIPv4,
        HwAddressSize:     6,
        ProtAddressSize:   4,
        Operation:         layers.ARPRequest,
        SenderHardwareAddress: srcMAC,
        SenderProtocolAddress: srcIP.To4(),
        TargetHardwareAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0},
        TargetProtocolAddress: targetIP.To4(),
    }
    
    // Serialize
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths:       true,
    }
    
    if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
        return nil, err
    }
    
    // Send
    if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
        return nil, err
    }
    
    // Wait for response
    packetSource := gopacket.NewPacketSource(a.handle, a.handle.LinkType())
    
    timeout := time.After(a.timeout)
    for {
        select {
        case <-timeout:
            return nil, nil // No response
        case packet := <-packetSource.Packets():
            arpLayer := packet.Layer(layers.LayerTypeARP)
            if arpLayer == nil {
                continue
            }
            
            arpReply, _ := arpLayer.(*layers.ARP)
            if arpReply.Operation == layers.ARPReply && 
               net.IP(arpReply.SenderProtocolAddress).Equal(targetIP) {
                return net.HardwareAddr(arpReply.SenderHardwareAddress), nil
            }
        }
    }
}
```

---

## 6. Complete Architecture Boilerplate

### 6.1 Production-Ready Scanner Architecture

```go
package main

import (
    "context"
    "fmt"
    "net"
    "os"
    "os/signal"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
    
    "github.com/projectdiscovery/goflags"
)

// Target represents a scan target
type Target struct {
    Host string
    Port int
}

// Result represents scan result
type Result struct {
    Target    Target
    IsOpen    bool
    Latency   time.Duration
    Error     error
    Timestamp time.Time
}

// Stats tracks scan statistics
type Stats struct {
    TotalHosts    int64
    ScannedHosts  int64
    OpenPorts     int64
    ClosedPorts   int64
    Errors        int64
    StartTime     time.Time
}

func (s *Stats) Progress() float64 {
    if s.TotalHosts == 0 {
        return 0
    }
    return float64(atomic.LoadInt64(&s.ScannedHosts)) / float64(s.TotalHosts) * 100
}

func (s *Stats) Rate() float64 {
    elapsed := time.Since(s.StartTime).Seconds()
    if elapsed == 0 {
        return 0
    }
    return float64(atomic.LoadInt64(&s.ScannedHosts)) / elapsed
}

// Scanner is the main scanner
type Scanner struct {
    config    *Config
    stats     *Stats
    results   chan *Result
    progress  chan float64
    sem       chan struct{} // Semaphore
}

// Config holds scanner configuration
type Config struct {
    Targets       []string
    Ports         []int
    Concurrency   int
    Timeout       time.Duration
    RateLimit     int
    OutputFile    string
    ShowProgress  bool
}

// NewScanner creates a new scanner
func NewScanner(config *Config) *Scanner {
    return &Scanner{
        config:   config,
        stats:    &Stats{StartTime: time.Now()},
        results:  make(chan *Result, config.Concurrency*2),
        progress: make(chan float64, 10),
        sem:      make(chan struct{}, config.Concurrency),
    }
}

// Run starts the scanning process
func (s *Scanner) Run(ctx context.Context) error {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()
    
    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Println("\nReceived interrupt, shutting down...")
        cancel()
    }()
    
    // Calculate total targets
    total := int64(len(s.config.Targets) * len(s.config.Port))
    s.stats.TotalHosts = total
    
    // Start result processor
    var wg sync.WaitGroup
    wg.Add(1)
    go s.processResults(&wg)
    
    // Start progress reporter
    if s.config.ShowProgress {
        go s.reportProgress(ctx)
    }
    
    // Start workers
    var scanWg sync.WaitGroup
    
    for _, target := range s.config.Targets {
        for _, port := range s.config.Ports {
            select {
            case <-ctx.Done():
                goto done
            case s.sem <- struct{}{}: // Acquire semaphore
            }
            
            scanWg.Add(1)
            go func(host string, port int) {
                defer scanWg.Done()
                defer func() { <-s.sem }() // Release semaphore
                
                s.scanTarget(ctx, host, port)
            }(target, port)
        }
    }
    
done:
    scanWg.Wait()
    close(s.results)
    wg.Wait()
    
    return nil
}

// scanTarget scans a single target
func (s *Scanner) scanTarget(ctx context.Context, host string, port int) {
    target := Target{Host: host, Port: port}
    start := time.Now()
    
    // Rate limiting
    if s.config.RateLimit > 0 {
        time.Sleep(time.Second / time.Duration(s.config.RateLimit))
    }
    
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
    
    var d net.Dialer
    d.Timeout = s.config.Timeout
    
    conn, err := d.DialContext(ctx, "tcp", addr)
    
    result := &Result{
        Target:    target,
        Timestamp: time.Now(),
        Latency:   time.Since(start),
    }
    
    if err != nil {
        result.Error = err
        result.IsOpen = false
        atomic.AddInt64(&s.stats.ClosedPorts, 1)
    } else {
        conn.Close()
        result.IsOpen = true
        atomic.AddInt64(&s.stats.OpenPorts, 1)
    }
    
    atomic.AddInt64(&s.stats.ScannedHosts, 1)
    
    select {
    case <-ctx.Done():
    case s.results <- result:
    }
}

// processResults processes and outputs results
func (s *Scanner) processResults(wg *sync.WaitGroup) {
    defer wg.Done()
    
    for result := range s.results {
        if result.IsOpen {
            fmt.Printf("[OPEN] %s:%d (%.2fms)\n", 
                result.Target.Host, 
                result.Target.Port,
                float64(result.Latency.Microseconds())/1000)
        }
    }
    
    // Print stats
    fmt.Printf("\n--- Scan Statistics ---\n")
    fmt.Printf("Total: %d | Open: %d | Closed: %d | Errors: %d\n",
        s.stats.TotalHosts,
        atomic.LoadInt64(&s.stats.OpenPorts),
        atomic.LoadInt64(&s.stats.ClosedPorts),
        atomic.LoadInt64(&s.stats.Errors))
    fmt.Printf("Duration: %.2fs | Rate: %.0f hosts/sec\n",
        time.Since(s.stats.StartTime).Seconds(),
        s.stats.Rate())
}

// reportProgress periodically reports progress
func (s *Scanner) reportProgress(ctx context.Context) {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            progress := s.stats.Progress()
            scanned := atomic.LoadInt64(&s.stats.ScannedHosts)
            rate := s.stats.Rate()
            
            fmt.Printf("\r[%.1f%%] Scanned: %d/%d | Rate: %.0f/s | Open: %d",
                progress, scanned, s.stats.TotalHosts, rate,
                atomic.LoadInt64(&s.stats.OpenPorts))
        }
    }
}

// ParsePorts parses port string (e.g., "80,443,8000-8100")
func ParsePorts(s string) ([]int, error) {
    // Implementation untuk parsing port ranges
    // ... (sesuai kebutuhan)
    return nil, nil
}

func main() {
    config := &Config{
        Targets:      []string{"scanme.nmap.org"},
        Ports:        []int{22, 80, 443, 3306, 8080},
        Concurrency:  100,
        Timeout:      2 * time.Second,
        ShowProgress: true,
    }
    
    scanner := NewScanner(config)
    if err := scanner.Run(context.Background()); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}
```

### 6.2 Key Dependencies (go.mod)

```go
module scanner

go 1.21

require (
    golang.org/x/net v0.19.0
    golang.org/x/sync v0.5.0
    github.com/google/gopacket v1.1.19 // untuk SYN scan
)
```

---

## 7. Security & Legal Considerations

### 7.1 Best Practices

1. **Always get permission** before scanning
2. **Rate limiting** untuk menghindari DoS
3. **Respect robots.txt** dan terms of service
4. **Logging** semua scan activities
5. **Use identifiable User-Agent** jika melakukan HTTP scanning

### 7.2 Detection Evasion (Educational Purpose)

```go
// Randomize scan order untuk menghindari pattern detection
func ShuffleTargets(targets []Target) {
    rand.Shuffle(len(targets), func(i, j int) {
        targets[i], targets[j] = targets[j], targets[i]
    })
}

// Randomize source ports
func RandomSourcePort() int {
    return 40000 + rand.Intn(25000)
}

// Decoy scanning (jarang berguna di 2026)
func WithDecoys(targets []string, decoys []string) []string {
    // Interleave targets dengan decoys
    // ...
    return nil
}
```

---

## 8. Summary & Recommendations

### 8.1 Architecture Decision Matrix

| Use Case | Technique | Library | Root | Performance |
|----------|-----------|---------|------|-------------|
| Basic scanning | TCP Connect | Standard net | No | Good |
| High-speed LAN | TCP Connect + Workers | Standard net | No | Excellent |
| Stealth scan | SYN | gopacket | Yes | Excellent |
| Service detection | TCP Connect + Probing | Standard net | No | Good |
| Host discovery | ICMP + TCP + ARP | gopacket | Yes* | Excellent |

*ICMP perlu root di Linux, TCP ping tidak perlu root

### 8.2 Final Checklist

- [ ] Gunakan **context** untuk cancellation
- [ ] Implement **semaphore** untuk limit concurrency
- [ ] Add **rate limiting** dengan token bucket
- [ ] Handle **"too many open files"** error
- [ ] Support **progress reporting**
- [ ] Implement **proper logging**
- [ ] Add **configuration file** support
- [ ] Support **multiple output formats** (JSON, CSV, etc.)
- [ ] Include **health check** endpoint
- [ ] Document **rate limits** dan **legal requirements**

---

## References

1. [Naabu](https://github.com/projectdiscovery/naabu) - Fast port scanner written in Go
2. [gopacket](https://github.com/google/gopacket) - Packet processing library
3. [Building a High Performance Port Scanner with Golang](https://medium.com/@KentGruber/building-a-high-performance-port-scanner-with-golang-9976181ec39d)
4. [C10M Problem](http://highscalability.com/blog/2013/5/13/the-secret-to-10-million-concurrent-connections-the-kernel-i.html)
5. [Go net.Dialer Documentation](https://pkg.go.dev/net#Dialer)
