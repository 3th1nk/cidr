package cidr

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
)

// CIDR https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
type CIDR struct {
	ip    net.IP
	ipNet *net.IPNet
}

// Parse parses s as a CIDR notation IP address and mask length,
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC4632 and RFC4291
func Parse(s string) (*CIDR, error) {
	i, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &CIDR{ip: i, ipNet: n}, nil
}

func ParseNoError(s string) *CIDR {
	c, _ := Parse(s)
	return c
}

// Equal reports whether cidr and ns are the same CIDR
func (c CIDR) Equal(ns string) bool {
	c2, err := Parse(ns)
	if err != nil {
		return false
	}
	return c.ipNet.IP.Equal(c2.ipNet.IP)
}

// IsIPv4 reports whether the CIDR is IPv4
func (c CIDR) IsIPv4() bool {
	_, bits := c.ipNet.Mask.Size()
	return bits/8 == net.IPv4len
}

// IsIPv6 reports whether the CIDR is IPv6
func (c CIDR) IsIPv6() bool {
	_, bits := c.ipNet.Mask.Size()
	return bits/8 == net.IPv6len
}

// Contains reports whether the CIDR includes ip
func (c CIDR) Contains(ip string) bool {
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false
	}
	return c.ipNet.Contains(ipObj)
}

// CIDR return the CIDR which ip prefix be corrected by the mask length.
// For example, "192.0.2.10/24" return "192.0.2.0/24"
func (c CIDR) CIDR() *net.IPNet {
	return c.ipNet
}

// String returns the CIDR string
func (c CIDR) String() string {
	return c.ipNet.String()
}

// IP returns the original IP prefix of the input CIDR
func (c CIDR) IP() net.IP {
	return c.ip
}

// Network returns network of the CIDR
func (c CIDR) Network() net.IP {
	return c.ipNet.IP
}

// MaskSize returns the number of leading ones and total bits in the CIDR mask
func (c CIDR) MaskSize() (ones, bits int) {
	ones, bits = c.ipNet.Mask.Size()
	return
}

// Mask returns mask of the CIDR
func (c CIDR) Mask() net.IP {
	mask, _ := hex.DecodeString(c.ipNet.Mask.String())
	return mask
}

// Gateway returns a gateway of the CIDR
func (c CIDR) Gateway() net.IP {
	if c.IsIPv4() {
		ip4 := c.ip.To4()
		ip4[3]++
		return ip4
	} else if c.IsIPv6() {
		ip6 := c.ip.To16()
		ip6[15]++
		return ip6
	}
	return nil
}

// Broadcast returns broadcast of the CIDR
func (c CIDR) Broadcast() net.IP {
	mask := c.ipNet.Mask
	bcst := make(net.IP, len(c.ipNet.IP))
	copy(bcst, c.ipNet.IP)
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.ipNet.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	return bcst
}

// IPRange returns begin and end ip of the CIDR
func (c CIDR) IPRange() (begin, end net.IP) {
	return c.Network(), c.Broadcast()
}

// IPCount returns ip total of the CIDR
func (c CIDR) IPCount() *big.Int {
	ones, bits := c.ipNet.Mask.Size()
	return big.NewInt(0).Lsh(big.NewInt(1), uint(bits-ones))
}

// Each iterate through each ip in the CIDR
func (c CIDR) Each(iterator func(ip string) bool) {
	next := make(net.IP, len(c.ipNet.IP))
	copy(next, c.ipNet.IP)
	for c.ipNet.Contains(next) {
		if !iterator(next.String()) {
			break
		}
		IPIncr(next)
	}
}

// EachFrom begin with specified ip, iterate through each ip in the CIDR
func (c CIDR) EachFrom(beginIP string, iterator func(ip string) bool) error {
	next := net.ParseIP(beginIP)
	if next == nil {
		return fmt.Errorf("invalid begin ip")
	}
	for c.ipNet.Contains(next) {
		if !iterator(next.String()) {
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
	var newOnes float64
	ones, bits := c.MaskSize()
	switch method {
	default:
		return nil, fmt.Errorf("unsupported method")

	case MethodSubnetNum:
		if num < 1 || (num&(num-1)) != 0 {
			return nil, fmt.Errorf("num must the power of 2")
		}

		newOnes = float64(ones) + math.Log2(float64(num))

	case MethodSubnetMask:
		newOnes = float64(num)

	case MethodHostNum:
		if num < 1 || (num&(num-1)) != 0 {
			return nil, fmt.Errorf("num must the power of 2")
		}

		newOnes = float64(bits) - math.Log2(float64(num))
	}

	// can't split when subnet mask greater than parent mask
	if newOnes < float64(ones) || newOnes > float64(bits) {
		return nil, fmt.Errorf("num must be between %v and %v", ones, bits)
	}

	// calculate subnet num
	// !!! if ones delta is too large, it will cause big memory allocation, even make slice panic when integer overflow !!!
	subnetNum := int(math.Pow(float64(2), newOnes-float64(ones)))

	cidrArr := make([]*CIDR, 0, subnetNum)
	network := make(net.IP, len(c.ipNet.IP))
	copy(network, c.ipNet.IP)
	for i := 0; i < subnetNum; i++ {
		cidr := ParseNoError(fmt.Sprintf("%v/%v", network.String(), int(newOnes)))
		cidrArr = append(cidrArr, cidr)
		network = cidr.Broadcast()
		IPIncr(network)
	}

	return cidrArr, nil
}

// SuperNetting merge network segments, must be contiguous
func SuperNetting(ns []string) (*CIDR, error) {
	num := len(ns)
	if num < 1 || (num&(num-1)) != 0 {
		return nil, fmt.Errorf("ns length must the power of 2")
	}

	mask := ""
	cidrs := make([]*CIDR, 0, num)
	for _, n := range ns {
		c, err := Parse(n)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR:%v", n)
		}
		cidrs = append(cidrs, c)

		// TODO only network segments with the same mask are supported
		if len(mask) == 0 {
			mask = c.Mask().String()
		} else if c.Mask().String() != mask {
			return nil, fmt.Errorf("not the same mask")
		}
	}
	SortCIDRAsc(cidrs)

	// check whether contiguous segments
	var network net.IP
	for _, c := range cidrs {
		if len(network) > 0 {
			if !network.Equal(c.ipNet.IP) {
				return nil, fmt.Errorf("not the contiguous segments")
			}
		}
		network = c.Broadcast()
		IPIncr(network)
	}

	// calculate parent segment by mask
	c := cidrs[0]
	ones, bits := c.MaskSize()
	ones = ones - int(math.Log2(float64(num)))
	c.ipNet.Mask = net.CIDRMask(ones, bits)
	c.ipNet.IP.Mask(c.ipNet.Mask)

	return c, nil
}
