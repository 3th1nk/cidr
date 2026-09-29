package cidr

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

var (
	bigIntOne = big.NewInt(1)
)

// CIDR https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
type CIDR struct {
	ip       net.IP
	ipNet    *net.IPNet
	original string
}

// Parse parses s as a CIDR notation IP address and mask length,
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC4632 and RFC4291.
// The returned error wraps ErrInvalidCIDR for invalid input.
func Parse(s string) (*CIDR, error) {
	i, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}
	return &CIDR{ip: i, ipNet: n, original: s}, nil
}

// ParseNoError parses s as a CIDR notation IP address and mask length,
// but ignores any error and returns nil on invalid input.
//
// Deprecated: use Parse and handle the error, or MustParse when the input
// is known to be valid. ParseNoError returns nil for invalid input, which
// may cause a nil pointer dereference.
func ParseNoError(s string) *CIDR {
	c, _ := Parse(s)
	return c
}

// MustParse parses s as a CIDR notation IP address and mask length,
// and panics on error. It is intended for use with constant inputs,
// in tests and program initialization.
func MustParse(s string) *CIDR {
	c, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("cidr: Parse(%q): %v", s, err))
	}
	return c
}

// ParseLoose parses s as a CIDR notation IP address and mask length,
// tolerating a bare IP address (treated as a single-host CIDR, e.g.
// "192.168.1.10" becomes "192.168.1.10/32") and host bits set in the
// IP part, which are masked to the network address
// (e.g. "192.168.1.10/24" becomes "192.168.1.0/24", while the original
// prefix is kept accessible via IP())
func ParseLoose(s string) (*CIDR, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCIDR, s)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		s = fmt.Sprintf("%v/%v", s, bits)
	}
	return Parse(s)
}

// CIDR returns the normalized network address based on the mask, not the original input.
//
//	For example, if the original input was "192.168.1.10/24", this returns a *net.IPNet representing "192.168.1.0/24".
func (c CIDR) CIDR() *net.IPNet {
	return c.ipNet
}

// String returns the normalized string representation of the CIDR
func (c CIDR) String() string {
	return c.ipNet.String()
}

// MarshalText implements encoding.TextMarshaler,
// returning the normalized string representation.
// As encoding/json uses TextMarshaler/TextUnmarshaler automatically,
// CIDR values marshal to a JSON string like "192.168.1.0/24".
func (c CIDR) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler,
// parsing the text as a CIDR (see Parse).
func (c *CIDR) UnmarshalText(b []byte) error {
	c2, err := Parse(string(b))
	if err != nil {
		return err
	}
	*c = *c2
	return nil
}

// IP returns the normalized IP prefix of the CIDR.
//
//	This method returns the IP address after processing IPv4-compatible and IPv4-mapped normalizations,
//
// but unlike Network() method, it does not correct the IP prefix based on the mask.
//
//	For example, if the original input was "192.168.1.10/24", this returns "192.168.1.10",
//
// while Network() would return "192.168.1.0" (the network address with host bits set to zero).
func (c CIDR) IP() net.IP {
	return c.ip
}

// Network returns the network address of the CIDR
func (c CIDR) Network() net.IP {
	return c.ipNet.IP
}
