package cidr

import (
	"fmt"
	"net"
)

// Mask returns the network mask of the CIDR as a net.IPMask.
//
//	Note that calling mask.String() directly returns a hex string without separators (e.g., "ffffff00"),
//
// which is not human-readable.
//
//	Use net.IP(mask).String() to get a human-readable representation:
//	- for IPv4, dotted decimal notation (e.g., "255.255.255.0")
//	- for IPv6, colon-separated hexadecimal notation (e.g., "ffff:ffff:ffff:ffff::")
func (c CIDR) Mask() net.IPMask {
	return c.ipNet.Mask
}

// DottedMask returns the mask in human-readable form: dotted-decimal
// notation for IPv4 (e.g. "255.255.255.0") or hex-colon notation
// for IPv6 (e.g. "ffff:ffff::")
func (c CIDR) DottedMask() string {
	return net.IP(c.ipNet.Mask).String()
}

// WildcardMask returns the inverse of the network mask in dotted-decimal
// notation (e.g. "0.0.0.255", as used in Cisco ACL configuration).
// It returns an empty string for pure IPv6 CIDRs.
func (c CIDR) WildcardMask() string {
	mask := c.ipNet.Mask
	if len(mask) == net.IPv6len {
		if c.isV6Family() {
			return ""
		}
		mask = mask[12:] // v4-mapped: take the low 32 bits
	}
	inv := make(net.IPMask, len(mask))
	for i := range mask {
		inv[i] = ^mask[i]
	}
	return net.IP(inv).String()
}

// MaskToPrefix converts a dotted-decimal (e.g. "255.255.255.0") or
// hex-colon (e.g. "ffff:ffff::") netmask into a prefix length.
// It returns an error wrapping ErrInvalidMask if s is not a valid
// contiguous netmask.
func MaskToPrefix(s string) (int, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidIP, s)
	}
	mask := net.IPMask(ip.To4())
	if mask == nil {
		mask = net.IPMask(ip.To16())
	}
	ones, total := mask.Size()
	if total == 0 {
		return 0, fmt.Errorf("%w: %v", ErrInvalidMask, s)
	}
	return ones, nil
}
