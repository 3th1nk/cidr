package cidr

import (
	"fmt"
	"math"
	"net"
)

const maxSubnetNum = 65536 // 2^16, reasonable limit to prevent memory issues

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

// SuperNetting merge network segments, must be contiguous.
// Unlike CollapseCIDRs, the segments must have the same mask, be
// contiguous and be a power of 2 in count; for arbitrary lists use
// CollapseCIDRs instead.
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
