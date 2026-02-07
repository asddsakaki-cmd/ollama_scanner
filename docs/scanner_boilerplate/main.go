// Production-Ready TCP Port Scanner in Go (2026)
// Features: 10000+ concurrent connections, rate limiting, context cancellation, progress reporting

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/semaphore"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	Targets      []string
	Ports        []int
	Concurrency  int
	Timeout      time.Duration
	RateLimit    int           // Packets per second (0 = unlimited)
	RetryCount   int
	WarmUpTime   time.Duration
	OutputFile   string
	JSONOutput   bool
	Silent       bool
	ShowProgress bool
}

func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("no targets specified")
	}
	if len(c.Ports) == 0 {
		return fmt.Errorf("no ports specified")
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 100
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	return nil
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

type Result struct {
	Target    Target        `json:"target"`
	IsOpen    bool          `json:"is_open"`
	Latency   time.Duration `json:"latency_ms"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

func (r Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	return json.Marshal(&struct {
		Latency float64 `json:"latency_ms"`
		*Alias
	}{
		Latency: float64(r.Latency.Microseconds()) / 1000,
		Alias:   (*Alias)(&r),
	})
}

type Stats struct {
	TotalHosts   int64
	ScannedHosts int64
	OpenPorts    int64
	ClosedPorts  int64
	Errors       int64
	StartTime    time.Time
	mu           sync.RWMutex
}

func (s *Stats) Progress() float64 {
	total := atomic.LoadInt64(&s.TotalHosts)
	if total == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.ScannedHosts)) / float64(total) * 100
}

func (s *Stats) Rate() float64 {
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.ScannedHosts)) / elapsed
}

func (s *Stats) ETA() time.Duration {
	rate := s.Rate()
	if rate == 0 {
		return 0
	}
	remaining := s.TotalHosts - atomic.LoadInt64(&s.ScannedHosts)
	return time.Duration(float64(remaining)/rate) * time.Second
}

// ============================================================================
// RATE LIMITER
// ============================================================================

type TokenBucket struct {
	rate       float64
	bucketSize float64
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewTokenBucket(rate int) *TokenBucket {
	if rate <= 0 {
		return nil
	}
	return &TokenBucket{
		rate:       float64(rate),
		bucketSize: float64(rate),
		tokens:     float64(rate),
		lastUpdate: time.Now(),
	}
}

func (tb *TokenBucket) Wait() {
	if tb == nil {
		return
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.bucketSize {
		tb.tokens = tb.bucketSize
	}

	if tb.tokens < 1 {
		waitTime := time.Duration((1-tb.tokens)/tb.rate*float64(time.Second)) + time.Millisecond
		time.Sleep(waitTime)
		tb.tokens = 0
	} else {
		tb.tokens--
	}
}

// ============================================================================
// PORT SCANNER
// ============================================================================

type PortScanner struct {
	config      *Config
	stats       *Stats
	semaphore   *semaphore.Weighted
	rateLimiter *TokenBucket
	dialer      *net.Dialer
}

func NewPortScanner(config *Config) *PortScanner {
	return &PortScanner{
		config:      config,
		stats:       &Stats{StartTime: time.Now()},
		semaphore:   semaphore.NewWeighted(int64(config.Concurrency)),
		rateLimiter: NewTokenBucket(config.RateLimit),
		dialer: &net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: -1, // Disable keep-alive for scanning
		},
	}
}

func (ps *PortScanner) Scan(ctx context.Context) (<-chan Result, error) {
	// Calculate total targets
	ps.stats.TotalHosts = int64(len(ps.config.Targets) * len(ps.config.Ports))

	results := make(chan Result, ps.config.Concurrency*4)

	var wg sync.WaitGroup

	// Start scanner goroutines
	for _, host := range ps.config.Targets {
		for _, port := range ps.config.Ports {
			target := Target{Host: host, Port: port}

			// Acquire semaphore
			if err := ps.semaphore.Acquire(ctx, 1); err != nil {
				break
			}

			wg.Add(1)
			go func(t Target) {
				defer wg.Done()
				defer ps.semaphore.Release(1)

				result := ps.scanPort(ctx, t)
				select {
				case <-ctx.Done():
					return
				case results <- result:
				}
			}(target)
		}
	}

	// Close results when all done
	go func() {
		wg.Wait()
		close(results)
	}()

	return results, nil
}

func (ps *PortScanner) scanPort(ctx context.Context, target Target) Result {
	start := time.Now()

	// Rate limiting
	ps.rateLimiter.Wait()

	addr := target.String()

	var result Result
	result.Target = target
	result.Timestamp = time.Now()

	// Try connection
	conn, err := ps.dialer.DialContext(ctx, "tcp", addr)

	if err != nil {
		result.Error = err.Error()
		result.IsOpen = false
		atomic.AddInt64(&ps.stats.ClosedPorts, 1)
	} else {
		conn.Close()
		result.IsOpen = true
		result.Latency = time.Since(start)
		atomic.AddInt64(&ps.stats.OpenPorts, 1)
	}

	atomic.AddInt64(&ps.stats.ScannedHosts, 1)
	return result
}

// ============================================================================
// OUTPUT HANDLER
// ============================================================================

type OutputHandler struct {
	config   *Config
	stats    *Stats
	openPorts []Result
	mu       sync.Mutex
}

func NewOutputHandler(config *Config, stats *Stats) *OutputHandler {
	return &OutputHandler{
		config:    config,
		stats:     stats,
		openPorts: make([]Result, 0),
	}
}

func (oh *OutputHandler) Process(results <-chan Result, done chan<- struct{}) {
	defer close(done)

	for result := range results {
		if result.IsOpen {
			oh.mu.Lock()
			oh.openPorts = append(oh.openPorts, result)
			oh.mu.Unlock()

			if !oh.config.Silent {
				oh.printResult(result)
			}
		}
	}

	// Sort results
	oh.mu.Lock()
	sort.Slice(oh.openPorts, func(i, j int) bool {
		if oh.openPorts[i].Target.Host == oh.openPorts[j].Target.Host {
			return oh.openPorts[i].Target.Port < oh.openPorts[j].Target.Port
		}
		return oh.openPorts[i].Target.Host < oh.openPorts[j].Target.Host
	})
	oh.mu.Unlock()

	// Final output
	if oh.config.OutputFile != "" {
		oh.saveToFile()
	}

	if !oh.config.Silent {
		oh.printSummary()
	}
}

func (oh *OutputHandler) printResult(r Result) {
	if oh.config.JSONOutput {
		data, _ := json.Marshal(r)
		fmt.Println(string(data))
	} else {
		fmt.Printf("[OPEN] %s:%d (%.2fms)\n",
			r.Target.Host,
			r.Target.Port,
			float64(r.Latency.Microseconds())/1000,
		)
	}
}

func (oh *OutputHandler) saveToFile() {
	file, err := os.Create(oh.config.OutputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	oh.mu.Lock()
	encoder.Encode(oh.openPorts)
	oh.mu.Unlock()
}

func (oh *OutputHandler) printSummary() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total Targets:    %d\n", oh.stats.TotalHosts)
	fmt.Printf("Scanned:          %d\n", atomic.LoadInt64(&oh.stats.ScannedHosts))
	fmt.Printf("Open Ports:       %d\n", atomic.LoadInt64(&oh.stats.OpenPorts))
	fmt.Printf("Closed/Filtered:  %d\n", atomic.LoadInt64(&oh.stats.ClosedPorts))
	fmt.Printf("Duration:         %.2fs\n", time.Since(oh.stats.StartTime).Seconds())
	fmt.Printf("Scan Rate:        %.0f hosts/sec\n", oh.stats.Rate())
	fmt.Println(strings.Repeat("=", 60))
}

func (oh *OutputHandler) ProgressReport() {
	if oh.config.Silent || !oh.config.ShowProgress {
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		progress := oh.stats.Progress()
		scanned := atomic.LoadInt64(&oh.stats.ScannedHosts)
		rate := oh.stats.Rate()
		eta := oh.stats.ETA()

		fmt.Printf("\r[%5.1f%%] Scanned: %d/%d | Rate: %4.0f/s | Open: %d | ETA: %s",
			progress,
			scanned,
			oh.stats.TotalHosts,
			rate,
			atomic.LoadInt64(&oh.stats.OpenPorts),
			formatDuration(eta),
		)

		if progress >= 100 {
			fmt.Println()
			return
		}
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func ParsePorts(portStr string) ([]int, error) {
	var ports []int

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for range
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}

			for i := start; i <= end; i++ {
				if i < 1 || i > 65535 {
					return nil, fmt.Errorf("port out of range: %d", i)
				}
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func ParseTargets(targetStr string) ([]string, error) {
	var targets []string

	parts := strings.Split(targetStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for CIDR
		if strings.Contains(part, "/") {
			ips, err := expandCIDR(part)
			if err != nil {
				return nil, err
			}
			targets = append(targets, ips...)
		} else {
			targets = append(targets, part)
		}
	}

	return targets, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	var config Config

	// Command line flags
	flag.StringVar(&config.OutputFile, "o", "", "Output file (JSON)")
	flag.BoolVar(&config.JSONOutput, "json", false, "Output results as JSON")
	flag.BoolVar(&config.Silent, "silent", false, "Silent mode (only output results)")
	flag.BoolVar(&config.ShowProgress, "progress", true, "Show progress bar")
	flag.IntVar(&config.Concurrency, "c", 100, "Concurrency level")
	flag.IntVar(&config.RateLimit, "rate", 0, "Rate limit (packets/sec, 0=unlimited)")
	flag.DurationVar(&config.Timeout, "timeout", 2*time.Second, "Connection timeout")

	targetsFlag := flag.String("t", "", "Targets (comma-separated, supports CIDR)")
	portsFlag := flag.String("p", "80,443", "Ports (comma-separated, supports ranges like 1-1000)")

	flag.Parse()

	// Parse targets
	if *targetsFlag == "" {
		// Check stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					config.Targets = append(config.Targets, line)
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: No targets specified. Use -t flag or pipe targets to stdin.")
			flag.Usage()
			os.Exit(1)
		}
	} else {
		targets, err := ParseTargets(*targetsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing targets: %v\n", err)
			os.Exit(1)
		}
		config.Targets = targets
	}

	// Parse ports
	ports, err := ParsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
		os.Exit(1)
	}
	config.Ports = ports

	// Validate
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print banner
	if !config.Silent {
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("Go Port Scanner 2026")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Targets:   %d hosts\n", len(config.Targets))
		fmt.Printf("Ports:     %d ports\n", len(config.Ports))
		fmt.Printf("Total:     %d combinations\n", len(config.Targets)*len(config.Ports))
		fmt.Printf("Workers:   %d\n", config.Concurrency)
		fmt.Printf("Timeout:   %v\n", config.Timeout)
		if config.RateLimit > 0 {
			fmt.Printf("Rate:      %d/sec\n", config.RateLimit)
		}
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println()
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !config.Silent {
			fmt.Println("\n\n[!] Interrupted, shutting down...")
		}
		cancel()
	}()

	// Set max parallelism
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Create scanner
	scanner := NewPortScanner(&config)

	// Create output handler
	outputHandler := NewOutputHandler(&config, scanner.stats)

	// Start progress reporter
	if config.ShowProgress && !config.Silent {
		go outputHandler.ProgressReport()
	}

	// Start scan
	results, err := scanner.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting scan: %v\n", err)
		os.Exit(1)
	}

	// Process results
	done := make(chan struct{})
	go outputHandler.Process(results, done)

	// Wait for completion
	<-done
}
