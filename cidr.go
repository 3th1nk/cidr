package cidr

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
)

/*
	https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
	CIDR表示法:
	IPv4   	网络号/前缀长度		192.168.1.0/24
	IPv6	接口号/前缀长度		2001:db8::/64
*/
type CIDR struct {
	ip      net.IP
	network *net.IPNet
}

func ParseCIDR(s string) (*CIDR, error) {
	i, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &CIDR{ip: i, network: n}, nil
}

// 判断是否IPv4
func (c CIDR) IsIPv4() bool {
	_, bits := c.network.Mask.Size()
	return bits/8 == net.IPv4len
}

// 判断是否IPv6
func (c CIDR) IsIPv6() bool {
	_, bits := c.network.Mask.Size()
	return bits/8 == net.IPv6len
}

// 有效的CIDR(传入的CIDR字符串中IP部分有可能不是网段的网络号)
func (c CIDR) CIDR() string {
	return c.network.String()
}

// CIDR字符串中的IP部分(不一定是网络号)
func (c CIDR) IP() string {
	return c.ip.String()
}

// 网络号
func (c CIDR) Network() string {
	return c.network.IP.String()
}

// 子网掩码位数
func (c CIDR) MaskSize() (ones, bits int) {
	ones, bits = c.network.Mask.Size()
	return
}

// 子网掩码
func (c CIDR) Mask() string {
	mask, _ := hex.DecodeString(c.network.Mask.String())
	return net.IP([]byte(mask)).String()
}

// 网关(默认为网段第二个IP)
func (c CIDR) Gateway() string {
	gateway := ""
	next := c.network.IP
	for step := 0; step < 2 && c.network.Contains(next); step++ {
		gateway = next.String()
		IPIncr(next)
	}
	return gateway
}

// 广播地址(网段最后一个IP)
func (c CIDR) Boardcast() string {
	// TODO 优化: 广播地址 = 网络号 | (~子网掩码)

	// IP字符串转换成二进制字符串
	var bs []byte
	for _, b := range c.network.IP {
		for i := 0; i < 8; i++ {
			b2 := b
			b <<= 1
			b >>= 1
			switch b2 {
			default:
				bs = append(bs, byte(1))
			case b:
				bs = append(bs, byte(0))
			}
			b <<= 1
		}
	}

	// 将主机号的二进制位全部置为1则是广播地址
	ones, bits := c.network.Mask.Size()
	for i := ones; i < bits; i++ {
		bs[i] = byte(1)
	}

	// 二进制字符串还原成IP字符串
	var s []byte
	var n uint8
	for i, v := range bs {
		m := i % 8
		n += uint8(v)
		if m == 7 {
			s = append(s, n)
			n = 0
		} else {
			n <<= 1
		}
	}

	return net.IP(s).String()
}

// 起始IP、结束IP
func (c CIDR) IPRange() (startIP, endIP string) {
	return c.Network(), c.Boardcast()
}

// 网段下所有IP, 包含网络号、主机可用地址(含网关地址)、广播地址
func (c CIDR) AllIP(ips chan<- string) {
	next := c.ip.Mask(c.network.Mask)
	for c.network.Contains(next) {
		ips <- next.String()
		IPIncr(next)
	}
	close(ips)
}

// IP地址自增
func IPIncr(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// 判断ip是否包含在网段中
func (c CIDR) Contains(ip string) bool {
	return c.network.Contains(net.ParseIP(ip))
}

// 裂解子网的方式
const (
	SUBNETTING_METHOD_SUBNET_NUM = 0 // 基于子网数量
	SUBNETTING_METHOD_HOST_NUM   = 1 // 基于主机数量
)

// 裂解子网
func (c CIDR) SubNetting(method, num int) ([]*CIDR, error) {
	if num < 1 || (num&(num-1)) != 0 {
		return nil, fmt.Errorf("裂解数量必须是2的次方")
	}

	ones, bits := c.MaskSize()
	dstOnes := ones
	if method == SUBNETTING_METHOD_SUBNET_NUM {
		dstOnes = ones + int(math.Log2(float64(num)))
	} else if method == SUBNETTING_METHOD_HOST_NUM {
		dstOnes = bits - int(math.Log2(float64(num)))
		// 如果子网的掩码位数和父网段一样，说明不能再裂解啦
		if dstOnes <= ones {
			return nil, nil
		}
		// 主机数量转换为子网数量
		num = int(math.Pow(float64(2), float64(dstOnes-ones)))
	} else {
		return nil, fmt.Errorf("不支持的裂解方式")
	}

	cidrs := []*CIDR{}
	network := c.network.IP
	for i := 0; i < num; i++ {
		cidr, _ := ParseCIDR(fmt.Sprintf("%v/%v", network.String(), dstOnes))
		cidrs = append(cidrs, cidr)

		// 广播地址的下一个IP即为下一段的网络号
		network = net.ParseIP(cidr.Boardcast())
		IPIncr(network)
	}

	return cidrs, nil
}

type CIDRList []*CIDR

func (c CIDRList) Len() int      { return len(c) }
func (c CIDRList) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c CIDRList) Less(i, j int) bool {
	// TODO 暂且由外部保证协议类型相同

	// 掩码不同时，比较掩码长度，掩码长度越大，网段越小
	c1ones, _ := c[i].MaskSize()
	c2ones, _ := c[j].MaskSize()
	if c1ones > c2ones {
		return true
	} else if c1ones < c2ones {
		return false
	}

	// 掩码相同时，比较网络号，网络号越小，网段越小
	for n := 0; n < len(c[i].network.IP); n++ {
		if c[i].network.IP[n] > c[j].network.IP[n] {
			return false
		} else if c[i].network.IP[n] < c[j].network.IP[n] {
			return true
		}
	}
	return false
}

// 子网合并
func SuperNetting(ns []string) (*CIDR, error) {

	// 子网数量必须是2的次方
	num := len(ns)
	if num < 1 || (num&(num-1)) != 0 {
		return nil, fmt.Errorf("子网数量必须是2的次方")
	}

	mask := ""
	cidrs := CIDRList{}
	for _, n := range ns {
		// 检查子网CIDR有效性
		c, err := ParseCIDR(n)
		if err != nil {
			return nil, fmt.Errorf("网段%v格式错误", n)
		}
		cidrs = append(cidrs, c)

		// 暂只考虑相同子网掩码的网段合并
		if len(mask) == 0 {
			mask = c.Mask()
		} else if c.Mask() != mask {
			return nil, fmt.Errorf("子网掩码不一致")
		}
	}
	sort.Sort(cidrs)

	// 检查网段是否连续
	var network net.IP
	for _, c := range cidrs {
		if len(network) > 0 {
			if !network.Equal(c.network.IP) {
				return nil, fmt.Errorf("必须是连续的网段")
			}
		}
		network = net.ParseIP(c.Boardcast())
		IPIncr(network)
	}

	// 子网掩码左移，得到共同的父网段
	c := cidrs[0]
	ones, bits := c.MaskSize()
	ones = ones - int(math.Log2(float64(num)))
	c.network.Mask = net.CIDRMask(ones, bits)
	c.network.IP.Mask(c.network.Mask)

	return c, nil
}
