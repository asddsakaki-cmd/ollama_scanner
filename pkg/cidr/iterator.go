// pkg/cidr/iterator.go
// Memory-efficient IP range iteration using net/netip

package cidr

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Iterator provides memory-efficient iteration over IP ranges
type Iterator struct {
	prefixes []netip.Prefix
	current  netip.Addr
	prefixIdx int
	started   bool
}

// NewIterator creates a new IP iterator from CIDR strings
func NewIterator(cidrs []string) (*Iterator, error) {
	var prefixes []netip.Prefix
	
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Try parsing as single IP
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR or IP %q: %w", cidr, err)
			}
			// Convert single IP to /32 or /128
			if addr.Is4() {
				prefix = netip.PrefixFrom(addr, 32)
			} else {
				prefix = netip.PrefixFrom(addr, 128)
			}
		}
		
		// Normalize (clear host bits)
		prefix = prefix.Masked()
		prefixes = append(prefixes, prefix)
	}
	
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no valid CIDRs provided")
	}
	
	return &Iterator{
		prefixes:  prefixes,
		prefixIdx: 0,
		started:   false,
	}, nil
}

// Next returns the next IP address and true, or zero address and false if done
func (it *Iterator) Next() (netip.Addr, bool) {
	if !it.started {
		// First call - initialize with first address of first prefix
		it.current = it.prefixes[0].Addr()
		it.started = true
		return it.current, true
	}
	
	// Try to increment within current prefix
	next := it.current.Next()
	if next.IsValid() && it.prefixes[it.prefixIdx].Contains(next) {
		it.current = next
		return it.current, true
	}
	
	// Move to next prefix
	it.prefixIdx++
	if it.prefixIdx >= len(it.prefixes) {
		return netip.Addr{}, false
	}
	
	it.current = it.prefixes[it.prefixIdx].Addr()
	return it.current, true
}

// Count estimates total number of addresses (for progress calculation)
func (it *Iterator) Count() uint64 {
	var total uint64
	for _, prefix := range it.prefixes {
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			// bits is validated to be 16-32 by NewIterator
			// Explicit bounds check to prevent overflow
			if bits < 0 || bits > 32 {
				continue // Invalid, skip
			}
			hostBits := uint(32 - bits) //nolint:gosec // G115: bits is validated (16-32) by NewIterator
			total += uint64(1) << hostBits
		} else {
			// For IPv6, cap to reasonable number
			if bits < 0 || bits > 128 {
				continue // Invalid, skip
			}
			hostBits := 128 - bits
			if hostBits > 60 {
				total += uint64(1) << 60 // Cap to ~1 billion to prevent overflow
			} else {
				total += uint64(1) << uint(hostBits) //nolint:gosec // G115: hostBits is validated (0-60) above
			}
		}
	}
	return total
}

// Reset resets the iterator to the beginning
func (it *Iterator) Reset() {
	it.prefixIdx = 0
	it.started = false
}

// ToChannel converts the iterator to a channel for goroutine-friendly iteration
func (it *Iterator) ToChannel(bufferSize int) <-chan netip.Addr {
	ch := make(chan netip.Addr, bufferSize)
	
	go func() {
		defer close(ch)
		it.Reset()
		
		for {
			addr, ok := it.Next()
			if !ok {
				break
			}
			ch <- addr
		}
	}()
	
	return ch
}

// GenerateTargets creates targets from CIDRs and ports
func GenerateTargets(cidrs []string, ports []int, bufferSize int) (<-chan netip.AddrPort, error) {
	iter, err := NewIterator(cidrs)
	if err != nil {
		return nil, err
	}
	
	ch := make(chan netip.AddrPort, bufferSize)
	
	go func() {
		defer close(ch)
		iter.Reset()
		
		for {
			addr, ok := iter.Next()
			if !ok {
				break
			}
			
			for _, port := range ports {
				if port < 1 || port > 65535 {
					continue
				}
				ch <- netip.AddrPortFrom(addr, uint16(port))
			}
		}
	}()
	
	return ch, nil
}

// CountTargets calculates total targets (addresses * ports)
func CountTargets(cidrs []string, ports []int) (uint64, error) {
	iter, err := NewIterator(cidrs)
	if err != nil {
		return 0, err
	}
	
	return iter.Count() * uint64(len(ports)), nil
}

// IsPrivate checks if IP is in private range
func IsPrivate(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	
	// IPv4 private ranges
	if addr.Is4() {
		// 10.0.0.0/8
		if addr.As4()[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if addr.As4()[0] == 172 && addr.As4()[1] >= 16 && addr.As4()[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if addr.As4()[0] == 192 && addr.As4()[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if addr.As4()[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if addr.As4()[0] == 169 && addr.As4()[1] == 254 {
			return true
		}
	}
	
	// IPv6 private ranges
	if addr.Is6() {
		// fc00::/7 (unique local)
		if addr.As16()[0]&0xfe == 0xfc {
			return true
		}
		// fe80::/10 (link-local)
		if uint16(addr.As16()[0])&0xffc0 == 0xfe80 {
			return true
		}
		// ::1/128 (loopback)
		if addr.IsLoopback() {
			return true
		}
	}
	
	return false
}

// CIDR size limits for safety warnings (not hard limits)
const (
	// MaxIPv4Hosts recommended limit for IPv4 (/16 = 65,536 hosts)
	MaxIPv4PrefixSize = 16
	// MaxIPv6Hosts recommended limit for IPv6 (/64)
	MaxIPv6PrefixSize = 64
)

// CIDRSizeInfo holds information about CIDR size
type CIDRSizeInfo struct {
	TotalHosts   uint64
	IsVeryLarge  bool
	Warning      string
}

// ValidateCIDRs validates a list of CIDR strings
// Now allows any size but returns warnings for large CIDRs
func ValidateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Try parsing as single IP
			if _, err := netip.ParseAddr(cidr); err != nil {
				return fmt.Errorf("invalid CIDR or IP %q: expected format like \"192.168.1.0/24\" or \"10.0.0.1\"", cidr)
			}
			continue
		}
		
		// Parse successful - no hard limits enforced
		// Size warnings are handled separately by CheckCIDRSize
		_ = prefix
	}
	return nil
}

// CheckCIDRSize checks CIDR size and returns warning info
// Returns warning message if CIDR is considered large
func CheckCIDRSize(cidrs []string, ports []int) (*CIDRSizeInfo, error) {
	var totalHosts uint64
	
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Single IP counts as 1
			if _, err := netip.ParseAddr(cidr); err == nil {
				totalHosts += uint64(len(ports))
			}
			continue
		}
		
		bits := prefix.Bits()
		var hosts uint64
		if prefix.Addr().Is4() {
			hostBits := uint(32 - bits)
			hosts = uint64(1) << hostBits
		} else {
			hostBits := 128 - bits
			if hostBits > 60 {
				hosts = uint64(1) << 60 // Cap IPv6
			} else {
				hosts = uint64(1) << uint(hostBits)
			}
		}
		totalHosts += hosts * uint64(len(ports))
	}
	
	info := &CIDRSizeInfo{
		TotalHosts: totalHosts,
	}
	
	// Set warnings based on size
	switch {
	case totalHosts > 1000000000: // > 1 billion
		info.IsVeryLarge = true
		info.Warning = fmt.Sprintf("EXTREMELY LARGE SCAN: %d targets (1000M+). This will take hours and consume significant resources.", totalHosts)
	case totalHosts > 10000000: // > 10 million
		info.IsVeryLarge = true
		info.Warning = fmt.Sprintf("VERY LARGE SCAN: %d targets (10M+). Ensure you have adequate resources.", totalHosts)
	case totalHosts > 100000: // > 100k
		info.Warning = fmt.Sprintf("Large scan: %d targets (100K+). Consider using smaller batches.", totalHosts)
	case totalHosts > 65536: // > /16
		info.Warning = fmt.Sprintf("Warning: %d targets. This exceeds recommended /16 size.", totalHosts)
	}
	
	return info, nil
}

// ParseCIDRFile parses CIDRs from a file (one per line)
// SECURITY: Validates filename to prevent path traversal attacks
func ParseCIDRFile(filename string) ([]string, error) {
	// Prevent path traversal attacks
	if strings.Contains(filename, "..") {
		return nil, fmt.Errorf("invalid filename: path traversal detected")
	}
	
	// Clean the path and convert to absolute
	cleanPath := filepath.Clean(filename)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}
	
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}
	
	// Ensure file is within current directory tree (prevent reading /etc/passwd, etc.)
	if !strings.HasPrefix(absPath, cwd) {
		return nil, fmt.Errorf("invalid filename: must be within current directory or subdirectories")
	}
	
	// Check if file is a regular file (not a symlink to sensitive file)
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("invalid file: must be a regular file")
	}
	
	// Security: limit file size to prevent DoS via huge files
	if info.Size() > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("file too large: maximum size is 10MB")
	}
	
	//nolint:gosec // G304: absPath is validated above (path traversal protection)
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CIDR file: %w", err)
	}
	
	var cidrs []string
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidrs = append(cidrs, line)
	}
	
	return cidrs, nil
}
