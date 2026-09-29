package cidr

import (
	"fmt"
	"math/big"
	"net"
	"sort"
)

// Supernet returns the parent CIDR covering c, with the mask shortened
// to newOnes (host bits in the network address are masked off).
// newOnes must be in [0, current mask prefix length].
func (c CIDR) Supernet(newOnes int) (*CIDR, error) {
	ones, bits := c.ipNet.Mask.Size()
	if newOnes < 0 || newOnes > ones {
		return nil, fmt.Errorf("%w: must be between %v and %v", ErrNumOutOfRange, newOnes, ones)
	}
	mask := net.CIDRMask(newOnes, bits)
	ipNet := &net.IPNet{IP: c.ipNet.IP.Mask(mask), Mask: mask}
	return &CIDR{ip: c.ip, ipNet: ipNet, original: c.original}, nil
}

// CollapseCIDRs merges the CIDRs into a normalized list: overlapping and
// adjacent CIDRs are merged, contained CIDRs are dropped, and the result
// is sorted ascending. Mixed families are grouped, IPv4 first.
// Unlike SuperNetting, the input CIDRs need neither the same mask,
// nor be contiguous, nor be a power of 2 in count.
func CollapseCIDRs(cs []*CIDR) []*CIDR {
	var v4s, v6s []*CIDR
	for _, c := range cs {
		if c == nil {
			continue
		}
		if c.isV6Family() {
			v6s = append(v6s, c)
		} else {
			v4s = append(v4s, c)
		}
	}

	var out []*CIDR
	for _, r := range collapseRanges(v4s) {
		out = append(out, r.toCIDRs()...)
	}
	for _, r := range collapseRanges(v6s) {
		out = append(out, r.toCIDRs()...)
	}
	return out
}

// RangeToCIDRs converts the IP range [start, end] into the minimal list
// of CIDRs covering it. start and end must be in the same family
// (IPv4 and IPv4-mapped are treated as the same family)
func RangeToCIDRs(start, end string) ([]*CIDR, error) {
	sIP, eIP := net.ParseIP(start), net.ParseIP(end)
	if sIP == nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIP, start)
	}
	if eIP == nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIP, end)
	}

	s4, e4 := sIP.To4(), eIP.To4()
	switch {
	case s4 != nil && e4 != nil:
		r := newIPRange(s4, e4, 4)
		if r.start.Cmp(r.end) > 0 {
			return nil, fmt.Errorf("%w: %v - %v", ErrInvalidRange, start, end)
		}
		return r.toCIDRs(), nil
	case s4 == nil && e4 == nil:
		r := newIPRange(sIP.To16(), eIP.To16(), 16)
		if r.start.Cmp(r.end) > 0 {
			return nil, fmt.Errorf("%w: %v - %v", ErrInvalidRange, start, end)
		}
		return r.toCIDRs(), nil
	default:
		return nil, fmt.Errorf("%w: %v - %v", ErrNotSameFamily, start, end)
	}
}

// SpanningCIDR returns the minimal CIDR covering all the given CIDRs,
// which must belong to the same family (IPv4 and IPv4-mapped are treated
// as the same family). It returns the CIDR itself for a single input.
func SpanningCIDR(cs []*CIDR) (*CIDR, error) {
	if len(cs) == 0 {
		return nil, fmt.Errorf("%w: empty cidr list", ErrInvalidCIDR)
	}

	v6f := cs[0].isV6Family()
	width := 4
	if v6f {
		width = 16
	}

	var minStart, maxEnd *big.Int
	for _, c := range cs {
		if c == nil {
			return nil, fmt.Errorf("%w: nil cidr in list", ErrInvalidCIDR)
		}
		if c.isV6Family() != v6f {
			return nil, fmt.Errorf("%w: %v", ErrNotSameFamily, c)
		}
		r := cidrToRange(c)
		if minStart == nil || r.start.Cmp(minStart) < 0 {
			minStart = r.start
		}
		if maxEnd == nil || r.end.Cmp(maxEnd) > 0 {
			maxEnd = r.end
		}
	}

	// the common prefix length equals bits minus the highest differing bit
	ones := width*8 - new(big.Int).Xor(minStart, maxEnd).BitLen()
	return newMaskedCIDR(bigToIP(minStart, width), ones, width*8), nil
}

// Exclude removes sub from c and returns the remaining blocks sorted
// ascending. sub must be a subnet of (or equal to) c; an equal sub
// yields an empty list.
func (c CIDR) Exclude(sub *CIDR) ([]*CIDR, error) {
	if sub == nil {
		return nil, fmt.Errorf("%w: nil sub cidr", ErrInvalidCIDR)
	}
	if c.isV6Family() != sub.isV6Family() {
		return nil, fmt.Errorf("%w: %v", ErrNotSameFamily, sub)
	}
	if !c.IsSupernetOf(sub) {
		return nil, fmt.Errorf("%w: %v", ErrIPNotInCIDR, sub)
	}
	if c.EqualNormalized(sub.String()) {
		return nil, nil
	}

	width := 4
	if c.isV6Family() {
		width = 16
	}
	toBig := func(ip net.IP) *big.Int {
		b := ip.To4()
		if width == 16 {
			b = ip.To16()
		}
		return new(big.Int).SetBytes(b)
	}

	var out []*CIDR
	cur := &c
	subOnes, _ := sub.ipNet.Mask.Size()
	for {
		curOnes, bits := cur.ipNet.Mask.Size()
		if curOnes >= subOnes {
			break
		}
		// split cur in half, keep the half not containing sub
		next := curOnes + 1
		curStart := toBig(cur.ipNet.IP)
		mid := new(big.Int).Add(curStart, new(big.Int).Lsh(bigIntOne, uint(bits-next)))
		if toBig(sub.ipNet.IP).Cmp(mid) < 0 {
			out = append(out, newMaskedCIDR(bigToIP(mid, width), next, bits))
			cur = newMaskedCIDR(bigToIP(curStart, width), next, bits)
		} else {
			out = append(out, newMaskedCIDR(bigToIP(curStart, width), next, bits))
			cur = newMaskedCIDR(bigToIP(mid, width), next, bits)
		}
	}
	SortCIDRAsc(out)
	return out, nil
}

// ipRange is a contiguous [start, end] range of width-byte IPs
type ipRange struct {
	start, end *big.Int
	width      int // 4 or 16
}

func newIPRange(start, end net.IP, width int) *ipRange {
	return &ipRange{start: new(big.Int).SetBytes(start), end: new(big.Int).SetBytes(end), width: width}
}

func cidrToRange(c *CIDR) *ipRange {
	if b := c.ipNet.IP.To4(); b != nil {
		return &ipRange{start: new(big.Int).SetBytes(b), end: new(big.Int).SetBytes(c.EndIP().To4()), width: 4}
	}
	return &ipRange{start: new(big.Int).SetBytes(c.ipNet.IP.To16()), end: new(big.Int).SetBytes(c.EndIP().To16()), width: 16}
}

// toCIDRs splits the range into the minimal list of aligned CIDRs
func (r *ipRange) toCIDRs() []*CIDR {
	var out []*CIDR
	bits := uint(r.width * 8)
	one := big.NewInt(1)
	start := new(big.Int).Set(r.start)
	for start.Cmp(r.end) <= 0 {
		// the largest aligned block: bounded by trailing zeros of start
		// and by the remaining range length (2^k <= end-start+1)
		k := bits
		if start.Sign() != 0 {
			k = start.TrailingZeroBits()
		}
		length := new(big.Int).Sub(r.end, start)
		length.Add(length, one)
		if k2 := uint(length.BitLen() - 1); k2 < k {
			k = k2
		}
		out = append(out, newMaskedCIDR(bigToIP(start, r.width), int(bits-k), int(bits)))
		start = new(big.Int).Add(start, new(big.Int).Lsh(one, k))
	}
	return out
}

// collapseRanges merges overlapping and adjacent CIDRs of the same family
// into maximal ranges
func collapseRanges(cs []*CIDR) []*ipRange {
	rs := make([]*ipRange, 0, len(cs))
	for _, c := range cs {
		rs = append(rs, cidrToRange(c))
	}
	sort.Slice(rs, func(i, j int) bool {
		if n := rs[i].start.Cmp(rs[j].start); n != 0 {
			return n < 0
		}
		return rs[i].end.Cmp(rs[j].end) > 0
	})

	merged := make([]*ipRange, 0, len(rs))
	for _, r := range rs {
		if n := len(merged); n > 0 && r.start.Cmp(new(big.Int).Add(merged[n-1].end, bigIntOne)) <= 0 {
			if r.end.Cmp(merged[n-1].end) > 0 {
				merged[n-1].end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

func bigToIP(n *big.Int, width int) net.IP {
	b := n.Bytes()
	ip := make(net.IP, width)
	copy(ip[width-len(b):], b)
	return ip
}

// newMaskedCIDR builds a CIDR from a network address and mask length
func newMaskedCIDR(network net.IP, ones, bits int) *CIDR {
	mask := net.CIDRMask(ones, bits)
	ipNet := &net.IPNet{IP: network.Mask(mask), Mask: mask}
	return &CIDR{ip: ipNet.IP, ipNet: ipNet, original: ipNet.String()}
}
