package cidr

import (
	"fmt"
	"net"
	"net/netip"
)

// AsNetip converts the CIDR to a netip.Prefix.
// IPv4-mapped CIDRs are unmapped to their IPv4 form
// (e.g. ::ffff:192.168.1.0/120 becomes 192.168.1.0/24).
func (c CIDR) AsNetip() (netip.Prefix, error) {
	ones, bits := c.ipNet.Mask.Size()
	if bits != 32 && bits != 128 {
		return netip.Prefix{}, fmt.Errorf("%w: invalid mask", ErrInvalidCIDR)
	}
	b := c.ipNet.IP.To16()
	if b == nil {
		return netip.Prefix{}, fmt.Errorf("%w: invalid network address", ErrInvalidCIDR)
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("%w: invalid network address", ErrInvalidCIDR)
	}
	addr = addr.Unmap()
	if bits == 128 && addr.Is4() {
		ones -= 96 // IPv4-mapped: /120 becomes /24
	}
	return netip.PrefixFrom(addr, ones), nil
}

// ParseNetip converts a netip.Prefix to a CIDR.
// Host bits set in the prefix address are masked to the network address.
func ParseNetip(p netip.Prefix) (*CIDR, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("%w: invalid netip prefix", ErrInvalidCIDR)
	}

	addr := p.Masked().Addr().Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}

	var network net.IP
	if addr.Is4() {
		a4 := addr.As4()
		network = net.IP(a4[:])
	} else {
		a16 := addr.As16()
		network = net.IP(a16[:])
	}
	ipNet := &net.IPNet{IP: network, Mask: net.CIDRMask(p.Bits(), bits)}
	return &CIDR{ip: network.To16(), ipNet: ipNet, original: ipNet.String()}, nil
}
