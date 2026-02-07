// pkg/cidr/iterator_test.go
// Unit tests for CIDR iterator

package cidr

import (
	"net/netip"
	"testing"
)

func TestNewIterator(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{
			name:    "valid single CIDR",
			cidrs:   []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name:    "valid multiple CIDRs",
			cidrs:   []string{"10.0.0.0/8", "172.16.0.0/12"},
			wantErr: false,
		},
		{
			name:    "valid single IP",
			cidrs:   []string{"192.168.1.1"},
			wantErr: false,
		},
		{
			name:    "empty CIDR list",
			cidrs:   []string{},
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			cidrs:   []string{"192.168.1.0/24", "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iter, err := NewIterator(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIterator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && iter == nil {
				t.Error("NewIterator() returned nil iterator without error")
			}
		})
	}
}

func TestIterator_Next(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		wantCount  int
		wantFirst  string
		wantLast   string
	}{
		{
			name:      "/30 subnet (4 IPs)",
			cidrs:     []string{"192.168.1.0/30"},
			wantCount: 4,
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.1.3",
		},
		{
			name:      "single IP",
			cidrs:     []string{"10.0.0.1"},
			wantCount: 1,
			wantFirst: "10.0.0.1",
			wantLast:  "10.0.0.1",
		},
		{
			name:      "two /30 subnets",
			cidrs:     []string{"192.168.1.0/30", "192.168.2.0/30"},
			wantCount: 8,
			wantFirst: "192.168.1.0",
			wantLast:  "192.168.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iter, err := NewIterator(tt.cidrs)
			if err != nil {
				t.Fatalf("NewIterator() error = %v", err)
			}

			var count int
			var first, last netip.Addr

			for {
				addr, ok := iter.Next()
				if !ok {
					break
				}
				if count == 0 {
					first = addr
				}
				last = addr
				count++
			}

			if count != tt.wantCount {
				t.Errorf("Iterator count = %d, want %d", count, tt.wantCount)
			}

			if first.String() != tt.wantFirst {
				t.Errorf("First address = %s, want %s", first.String(), tt.wantFirst)
			}

			if last.String() != tt.wantLast {
				t.Errorf("Last address = %s, want %s", last.String(), tt.wantLast)
			}
		})
	}
}

func TestIterator_Count(t *testing.T) {
	tests := []struct {
		name     string
		cidrs    []string
		want     uint64
	}{
		{
			name:  "/30 subnet",
			cidrs: []string{"192.168.1.0/30"},
			want:  4,
		},
		{
			name:  "/24 subnet",
			cidrs: []string{"192.168.1.0/24"},
			want:  256,
		},
		{
			name:  "single IP",
			cidrs: []string{"10.0.0.1"},
			want:  1,
		},
		{
			name:  "multiple subnets",
			cidrs: []string{"192.168.1.0/30", "10.0.0.0/30"},
			want:  8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iter, err := NewIterator(tt.cidrs)
			if err != nil {
				t.Fatalf("NewIterator() error = %v", err)
			}

			got := iter.Count()
			if got != tt.want {
				t.Errorf("Count() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIterator_Reset(t *testing.T) {
	iter, err := NewIterator([]string{"192.168.1.0/30"})
	if err != nil {
		t.Fatalf("NewIterator() error = %v", err)
	}

	// Iterate through all
	count1 := 0
	for {
		_, ok := iter.Next()
		if !ok {
			break
		}
		count1++
	}

	// Reset and iterate again
	iter.Reset()
	count2 := 0
	for {
		_, ok := iter.Next()
		if !ok {
			break
		}
		count2++
	}

	if count1 != count2 {
		t.Errorf("After reset, count = %d, want %d", count2, count1)
	}
}

func TestCountTargets(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
		ports []int
		want  uint64
	}{
		{
			name:  "/30 with 1 port",
			cidrs: []string{"192.168.1.0/30"},
			ports: []int{11434},
			want:  4,
		},
		{
			name:  "/30 with 3 ports",
			cidrs: []string{"192.168.1.0/30"},
			ports: []int{11434, 11435, 8080},
			want:  12,
		},
		{
			name:  "multiple cidrs with ports",
			cidrs: []string{"192.168.1.0/30", "10.0.0.0/30"},
			ports: []int{11434, 8080},
			want:  16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CountTargets(tt.cidrs, tt.ports)
			if err != nil {
				t.Fatalf("CountTargets() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("CountTargets() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16-31", "172.16.0.1", true},
		{"private 172.16-31", "172.31.255.255", true},
		{"private 192.168", "192.168.1.1", true},
		{"loopback", "127.0.0.1", true},
		{"link-local", "169.254.0.1", true},
		{"public", "8.8.8.8", false},
		{"public", "1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			got := IsPrivate(addr)
			if got != tt.want {
				t.Errorf("IsPrivate(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestValidateCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{
			name:    "valid list",
			cidrs:   []string{"192.168.1.0/24", "10.0.0.0/16"}, // /16 is max allowed
			wantErr: false,
		},
		{
			name:    "empty list",
			cidrs:   []string{},
			wantErr: false, // Empty is valid, just no targets
		},
		{
			name:    "with whitespace",
			cidrs:   []string{"  192.168.1.0/24  "},
			wantErr: false, // Should trim whitespace
		},
		{
			name:    "cidr too large ipv4",
			cidrs:   []string{"10.0.0.0/8"}, // /8 exceeds /16 limit
			wantErr: true,
		},
		{
			name:    "cidr too large ipv6",
			cidrs:   []string{"2000::/32"}, // /32 exceeds /64 limit
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDRs(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCIDRs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
