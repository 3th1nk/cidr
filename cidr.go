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
	ipnet *net.IPNet
}

// ParseCIDR parses s as a CIDR notation IP address and mask length,
// like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC 4632 and RFC 4291
func ParseCIDR(s string) (*CIDR, error) {
	i, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &CIDR{ip: i, ipnet: n}, nil
}

// Equal reports whether cidr and ns are the same CIDR
func (c CIDR) Equal(ns string) bool {
	c2, err := ParseCIDR(ns)
	if err != nil {
		return false
	}
	return c.ipnet.IP.Equal(c2.ipnet.IP)
}

// IsIPv4 reports whether the CIDR is IPv4
func (c CIDR) IsIPv4() bool {
	_, bits := c.ipnet.Mask.Size()
	return bits/8 == net.IPv4len
}

// IsIPv6 reports whether the CIDR is IPv6
func (c CIDR) IsIPv6() bool {
	_, bits := c.ipnet.Mask.Size()
	return bits/8 == net.IPv6len
}

// Contains reports whether the CIDR includes ip
func (c CIDR) Contains(ip string) bool {
	return c.ipnet.Contains(net.ParseIP(ip))
}

// CIDR returns the CIDR string. If the IP prefix of the input CIDR string is inaccurate, it returns the string which be corrected by the mask length. For example, "192.0.2.10/24" return "192.0.2.0/24"
func (c CIDR) CIDR() string {
	return c.ipnet.String()
}

// IP returns the original IP prefix of the input CIDR
func (c CIDR) IP() string {
	return c.ip.String()
}

// Network returns network of the CIDR
func (c CIDR) Network() string {
	return c.ipnet.IP.String()
}

// MaskSize returns the number of leading ones and total bits in the CIDR mask
func (c CIDR) MaskSize() (ones, bits int) {
	ones, bits = c.ipnet.Mask.Size()
	return
}

// Mask returns mask of the CIDR
func (c CIDR) Mask() string {
	mask, _ := hex.DecodeString(c.ipnet.Mask.String())
	return net.IP([]byte(mask)).String()
}

// Broadcast returns broadcast of the CIDR
func (c CIDR) Broadcast() string {
	mask := c.ipnet.Mask
	bcst := make(net.IP, len(c.ipnet.IP))
	copy(bcst, c.ipnet.IP)
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.ipnet.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	return bcst.String()
}

// IPRange returns begin and end ip of the CIDR
func (c CIDR) IPRange() (begin, end string) {
	return c.Network(), c.Broadcast()
}

// IPCount returns ip total of the CIDR
func (c CIDR) IPCount() *big.Int {
	ones, bits := c.ipnet.Mask.Size()
	return big.NewInt(0).Lsh(big.NewInt(1), uint(bits-ones))
}

// ForEachIP iterate through each ip in the CIDR
func (c CIDR) ForEachIP(iterator func(ip string) error) error {
	next := make(net.IP, len(c.ipnet.IP))
	copy(next, c.ipnet.IP)
	for c.ipnet.Contains(next) {
		if err := iterator(next.String()); err != nil {
			return err
		}
		IncrIP(next)
	}
	return nil
}

// ForEachIPBeginWith begin with specified ip, iterate through each ip in the CIDR
func (c CIDR) ForEachIPBeginWith(beginIP string, iterator func(ip string) error) error {
	next := net.ParseIP(beginIP)
	for c.ipnet.Contains(next) {
		if err := iterator(next.String()); err != nil {
			return err
		}
		IncrIP(next)
	}
	return nil
}

const (
	SUBNETTING_METHOD_SUBNET_NUM = 0
	SUBNETTING_METHOD_HOST_NUM   = 1
)

// SubNetting split network segment based on the number of hosts or subnets
func (c CIDR) SubNetting(method, num int) ([]*CIDR, error) {
	if num < 1 || (num&(num-1)) != 0 {
		return nil, fmt.Errorf("num must the power of 2")
	}

	newOnes := int(math.Log2(float64(num)))
	ones, bits := c.MaskSize()
	switch method {
	default:
		return nil, fmt.Errorf("unsupported method")

	case SUBNETTING_METHOD_SUBNET_NUM:
		newOnes = ones + newOnes
		// can't split when subnet mask greater than parent mask
		if newOnes > bits {
			return nil, nil
		}

	case SUBNETTING_METHOD_HOST_NUM:
		newOnes = bits - newOnes
		// can't split when subnet mask not greater than parent mask
		if newOnes <= ones {
			return nil, nil
		}
		// calculate subnet num by host num
		num = int(math.Pow(float64(2), float64(newOnes-ones)))
	}

	cidrs := []*CIDR{}
	network := make(net.IP, len(c.ipnet.IP))
	copy(network, c.ipnet.IP)
	for i := 0; i < num; i++ {
		cidr, _ := ParseCIDR(fmt.Sprintf("%v/%v", network.String(), newOnes))
		cidrs = append(cidrs, cidr)
		network = net.ParseIP(cidr.Broadcast())
		IncrIP(network)
	}

	return cidrs, nil
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
		c, err := ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format:%v", n)
		}
		cidrs = append(cidrs, c)

		// TODO only network segments with the same mask are supported
		if len(mask) == 0 {
			mask = c.Mask()
		} else if c.Mask() != mask {
			return nil, fmt.Errorf("not the same mask")
		}
	}
	AscSortCIDRs(cidrs)

	// check whether contiguous segments
	var network net.IP
	for _, c := range cidrs {
		if len(network) > 0 {
			if !network.Equal(c.ipnet.IP) {
				return nil, fmt.Errorf("not the contiguous segments")
			}
		}
		network = net.ParseIP(c.Broadcast())
		IncrIP(network)
	}

	// calculate parent segment by mask
	c := cidrs[0]
	ones, bits := c.MaskSize()
	ones = ones - int(math.Log2(float64(num)))
	c.ipnet.Mask = net.CIDRMask(ones, bits)
	c.ipnet.IP.Mask(c.ipnet.Mask)

	return c, nil
}
