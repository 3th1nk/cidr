package cidr

import (
	"bytes"
	"net"
	"strings"
)

// Equal reports whether cidr and ns are the same CIDR (excluding IPv4-mapped)
func (c CIDR) Equal(ns string) bool {
	c2, err := Parse(ns)
	if err != nil {
		return false
	}
	return c.ipNet.IP.Equal(c2.ipNet.IP) && bytes.Equal(c.ipNet.Mask, c2.ipNet.Mask)
}

// EqualFold reports whether cidr and ns are the same CIDR (including IPv4-mapped)
//
// Deprecated: use EqualNormalized instead, which has the same behavior and a clearer name.
func (c CIDR) EqualFold(ns string) bool {
	return c.EqualNormalized(ns)
}

// EqualNormalized reports whether cidr and ns are the same CIDR,
// comparing the normalized representation (including IPv4-mapped equivalence)
func (c CIDR) EqualNormalized(ns string) bool {
	c2, err := Parse(ns)
	if err != nil {
		return false
	}
	return c.ipNet.String() == c2.ipNet.String()
}

// IsIPv4 reports whether the CIDR is IPv4
func (c CIDR) IsIPv4() bool {
	_, bits := c.ipNet.Mask.Size()
	return bits == 32
}

// IsIPv6 reports whether the CIDR is IPv6 (including IPv4-compatible and IPv4-mapped)
func (c CIDR) IsIPv6() bool {
	_, bits := c.ipNet.Mask.Size()
	return bits == 128
}

// IsPureIPv6 reports whether the CIDR is IPv6 (excluding IPv4-compatible and IPv4-mapped)
func (c CIDR) IsPureIPv6() bool {
	if c.IsIPv6() {
		return !strings.Contains(c.original, ".")
	}
	return false
}

// Contains reports whether the CIDR includes ip
func (c CIDR) Contains(ip string) bool {
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false
	}
	return c.ipNet.Contains(ipObj)
}

// isV6Family reports whether the CIDR belongs to the pure IPv6 family,
// excluding IPv4 and IPv4-mapped CIDRs
func (c CIDR) isV6Family() bool {
	return c.IsIPv6() && !isIPv4Mapped(c.ipNet.IP)
}

// Overlaps reports whether c and o overlap (partially or fully).
// IPv4 (including IPv4-mapped) and pure IPv6 CIDRs are treated as
// different families and never overlap.
func (c CIDR) Overlaps(o *CIDR) bool {
	if o == nil || c.isV6Family() != o.isV6Family() {
		return false
	}
	cs, ce := c.IPRange()
	os, oe := o.IPRange()
	return IPCompare(cs, oe) <= 0 && IPCompare(os, ce) <= 0
}

// IsSubnetOf reports whether c is a subnet of o (or equal to it)
func (c CIDR) IsSubnetOf(o *CIDR) bool {
	if o == nil || c.isV6Family() != o.isV6Family() {
		return false
	}
	cOnes, _ := c.ipNet.Mask.Size()
	oOnes, _ := o.ipNet.Mask.Size()
	if cOnes < oOnes {
		return false
	}
	return o.ipNet.Contains(c.ipNet.IP)
}

// IsSupernetOf reports whether c is a supernet of o (or equal to it)
func (c CIDR) IsSupernetOf(o *CIDR) bool {
	if o == nil {
		return false
	}
	return o.IsSubnetOf(&c)
}
