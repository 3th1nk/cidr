package cidr

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
)

var (
	bigIntOne = big.NewInt(1)
)

// Errors returned by this package, can be checked with errors.Is
var (
	// ErrInvalidIP the given string is not a valid IP address
	ErrInvalidIP = errors.New("invalid ip")
	// ErrIPNotInCIDR the given IP is not within the CIDR
	ErrIPNotInCIDR = errors.New("ip is not in the cidr")
	// ErrInvalidCIDR the given string is not a valid CIDR
	ErrInvalidCIDR = errors.New("invalid cidr")
	// ErrInvalidNum the number (or the length of the segments) must be a power of 2
	ErrInvalidNum = errors.New("num must be a power of 2")
	// ErrNumOutOfRange the number is out of the allowed mask range
	ErrNumOutOfRange = errors.New("num out of range")
	// ErrExceedMaxLimit the number of subnets exceeds the maximum limit
	ErrExceedMaxLimit = errors.New("subnet number exceeds maximum limit")
	// ErrUnsupportedMethod the SubNetting method is not supported
	ErrUnsupportedMethod = errors.New("unsupported method")
	// ErrNotSameMask the CIDRs do not have the same mask
	ErrNotSameMask = errors.New("not the same mask")
	// ErrNotContiguous the segments are not contiguous
	ErrNotContiguous = errors.New("not contiguous segments")
	// ErrInvalidRange the given IP range is invalid (bad order or cross-family)
	ErrInvalidRange = errors.New("invalid ip range")
	// ErrNotSameFamily the CIDRs do not belong to the same address family
	ErrNotSameFamily = errors.New("not the same address family")
	// ErrInvalidMask the given string is not a valid contiguous netmask
	ErrInvalidMask = errors.New("invalid netmask")
)

const maxSubnetNum = 65536 // 2^16, reasonable limit to prevent memory issues

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

func isZeros(p net.IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
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

func isIPv4Mapped(ip net.IP) bool {
	return isZeros(ip[:10]) && ip[10] == 0xFF && ip[11] == 0xFF
}

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

type SubNettingMethod int

const (
	// MethodSubnetNum SubNetting based on the number of subnets
	MethodSubnetNum = SubNettingMethod(0)
	// MethodHostNum SubNetting based on the number of hosts
	MethodHostNum = SubNettingMethod(1)
	// MethodSubnetMask SubNetting based on the mask prefix length of subnets
	MethodSubnetMask = SubNettingMethod(2)
)

// SubNetting split network segment based on the number of hosts or subnets
func (c CIDR) SubNetting(method SubNettingMethod, num int) ([]*CIDR, error) {
	var newOnes int
	ones, bits := c.ipNet.Mask.Size()
	switch method {
	default:
		return nil, ErrUnsupportedMethod

	case MethodSubnetNum:
		if num < 1 || (num&(num-1)) != 0 {
			return nil, ErrInvalidNum
		}
		newOnes = ones + int(math.Log2(float64(num)))

	case MethodSubnetMask:
		newOnes = num

	case MethodHostNum:
		if num < 1 || (num&(num-1)) != 0 {
			return nil, ErrInvalidNum
		}
		newOnes = bits - int(math.Log2(float64(num)))
	}

	// can't split when subnet mask greater than parent mask
	if newOnes < ones || newOnes > bits {
		return nil, fmt.Errorf("%w: must be between %v and %v", ErrNumOutOfRange, ones, bits)
	}

	// calculate subnet num
	// check before shifting: shift over 16 exceeds maxSubnetNum (2^16),
	// and 1<<64+ would silently overflow int to 0
	if newOnes-ones > 16 {
		return nil, fmt.Errorf("%w: exceeds maximum limit of %d", ErrExceedMaxLimit, maxSubnetNum)
	}
	subnetNum := 1 << uint(newOnes-ones) // shift <= 16, no overflow

	cidrArr := make([]*CIDR, 0, subnetNum)
	network := make(net.IP, len(c.ipNet.IP))
	copy(network, c.ipNet.IP)
	for i := 0; i < subnetNum; i++ {
		cidr := MustParse(fmt.Sprintf("%v/%v", network.String(), newOnes))
		cidrArr = append(cidrArr, cidr)
		network = cidr.EndIP()
		IPIncr(network)
	}

	return cidrArr, nil
}

// SuperNetting merge network segments, must be contiguous
func SuperNetting(ns []string) (*CIDR, error) {
	num := len(ns)
	if num < 1 || (num&(num-1)) != 0 {
		return nil, ErrInvalidNum
	}

	var mask string
	cidrs := make([]*CIDR, 0, num)
	for _, n := range ns {
		c, err := Parse(n)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCIDR, n)
		}
		cidrs = append(cidrs, c)

		// TODO only network segments with the same mask are supported
		if len(mask) == 0 {
			mask = c.Mask().String()
		} else if c.Mask().String() != mask {
			return nil, ErrNotSameMask
		}
	}
	SortCIDRAsc(cidrs)

	// check whether contiguous segments
	var network net.IP
	for _, c := range cidrs {
		if len(network) > 0 {
			if !network.Equal(c.ipNet.IP) {
				return nil, ErrNotContiguous
			}
		}
		network = c.EndIP()
		IPIncr(network)
	}

	// calculate parent segment by mask
	c := cidrs[0]
	ones, bits := c.ipNet.Mask.Size()
	ones = ones - int(math.Log2(float64(num)))
	c.ipNet.Mask = net.CIDRMask(ones, bits)
	// net.IP.Mask returns a new IP, it does not modify in place
	c.ipNet.IP = c.ipNet.IP.Mask(c.ipNet.Mask)

	return c, nil
}
