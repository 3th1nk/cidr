package cidr

import (
	"fmt"
	"math/big"
	"net"
)

// Broadcast returns the broadcast address of the CIDR (only valid for IPv4)
func (c CIDR) Broadcast() net.IP {
	if c.IsIPv6() {
		if isIPv4Mapped(c.ipNet.IP) {
			return c.EndIP()
		}
		return nil
	}
	return c.EndIP()
}

// StartIP returns the start IP of the CIDR
func (c CIDR) StartIP() net.IP {
	return c.ipNet.IP
}

// EndIP returns the end IP of the CIDR
func (c CIDR) EndIP() net.IP {
	ip := make(net.IP, len(c.ipNet.IP))
	copy(ip, c.ipNet.IP)
	mask := c.ipNet.Mask
	for i := 0; i < len(mask); i++ {
		ipIdx := len(ip) - i - 1
		ip[ipIdx] = c.ipNet.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	return ip
}

// IPRange returns the start and end IP of the CIDR
func (c CIDR) IPRange() (start, end net.IP) {
	return c.StartIP(), c.EndIP()
}

// IPCount returns the number of IPs in the CIDR
func (c CIDR) IPCount() *big.Int {
	ones, bits := c.ipNet.Mask.Size()
	shift := uint(bits - ones)
	return big.NewInt(0).Lsh(bigIntOne, shift)
}

// HostCount returns the number of usable host addresses in the CIDR.
// For IPv4 the network and broadcast addresses are excluded, except for
// /31 (RFC 3021) and /32 which use all addresses; for IPv6 all addresses
// are counted.
func (c CIDR) HostCount() *big.Int {
	count := c.IPCount()
	if c.IsIPv4() {
		ones, _ := c.ipNet.Mask.Size()
		if ones >= 31 {
			return count
		}
		return count.Sub(count, big.NewInt(2))
	}
	return count
}

// NthHost returns the n-th usable host address (0-based), following the
// same host semantics as HostCount. It returns an error wrapping
// ErrNumOutOfRange if n is negative or exceeds HostCount-1.
func (c CIDR) NthHost(n int64) (net.IP, error) {
	if n < 0 {
		return nil, fmt.Errorf("%w: %d", ErrNumOutOfRange, n)
	}
	if hostCount := c.HostCount(); big.NewInt(n).Cmp(hostCount) >= 0 {
		return nil, fmt.Errorf("%w: %d >= host count %v", ErrNumOutOfRange, n, hostCount)
	}

	b := c.ipNet.IP.To4()
	size := 4
	if b == nil {
		b = c.ipNet.IP.To16()
		size = 16
	}
	offset := big.NewInt(n)
	if ones, _ := c.ipNet.Mask.Size(); c.IsIPv4() && ones < 31 {
		offset.Add(offset, bigIntOne) // skip the network address
	}
	addr := new(big.Int).Add(new(big.Int).SetBytes(b), offset)
	bs := addr.Bytes()
	ip := make(net.IP, size)
	copy(ip[size-len(bs):], bs)
	return ip, nil
}

// Each iterates over all IPs in the CIDR
func (c CIDR) Each(iterator func(ip string) bool) {
	next := make(net.IP, len(c.ipNet.IP))
	copy(next, c.ipNet.IP)
	endIP := c.EndIP()
	for c.ipNet.Contains(next) {
		if !iterator(next.String()) {
			break
		}
		if next.Equal(endIP) {
			break
		}
		IPIncr(next)
	}
}

// EachFrom iterates over all IPs in the CIDR from a given IP.
// It returns an error if beginIP is invalid or not within the CIDR.
func (c CIDR) EachFrom(beginIP string, iterator func(ip string) bool) error {
	next := net.ParseIP(beginIP)
	if next == nil {
		return fmt.Errorf("%w: %v", ErrInvalidIP, beginIP)
	}
	if !c.ipNet.Contains(next) {
		return fmt.Errorf("%w: %v", ErrIPNotInCIDR, beginIP)
	}
	endIP := c.EndIP()
	for c.ipNet.Contains(next) {
		if !iterator(next.String()) {
			break
		}
		if next.Equal(endIP) {
			break
		}
		IPIncr(next)
	}
	return nil
}
