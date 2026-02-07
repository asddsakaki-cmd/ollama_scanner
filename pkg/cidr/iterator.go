// pkg/cidr/iterator.go
// Memory-efficient IP range iteration using net/netip

package cidr

import (
	"fmt"
	"net/netip"
	"os"
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
			total += uint64(1) << uint(32-bits)
		} else {
			// For IPv6, cap to reasonable number
			hostBits := 128 - bits
			if hostBits > 60 {
				total += uint64(1) << 60 // Cap to ~1 billion to prevent overflow
			} else {
				total += uint64(1) << uint(hostBits)
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

// ValidateCIDRs validates a list of CIDR strings
func ValidateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		
		if _, err := netip.ParsePrefix(cidr); err != nil {
			if _, err := netip.ParseAddr(cidr); err != nil {
				return fmt.Errorf("invalid CIDR or IP %q", cidr)
			}
		}
	}
	return nil
}

// ParseCIDRFile parses CIDRs from a file (one per line)
func ParseCIDRFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
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
