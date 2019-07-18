package cidr_test

import (
	"cidr"
	"fmt"
	"testing"
)

func TestAllIP(t *testing.T) {
	c, _ := cidr.ParseCIDR("192.168.1.0/24")
	ips := make(chan string)
	go c.AllIP(ips)
	for {
		ip, ok := <-ips
		if !ok {
			fmt.Println("done")
			break
		}
		fmt.Println(ip)
	}
}

func TestMask(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	fmt.Println("IPv4:", c1.Mask())

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	fmt.Println("IPv6:", c2.Mask())
}

func TestBoardcast(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	fmt.Println("IPv4:", c1.Boardcast())

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	fmt.Println("IPv6:", c2.Boardcast())
}

func TestSubNeting(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	cs1, _ := c1.SubNeting(cidr.SUBNET_METHOD_BASE_SUBNET, 16)
	fmt.Println("IPv4子网划分:")
	for _, c := range cs1 {
		fmt.Println(c.CIDR())
	}

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	cs2, _ := c2.SubNeting(cidr.SUBNET_METHOD_BASE_SUBNET, 16)
	fmt.Println("IPv6子网划分:")
	for _, c := range cs2 {
		fmt.Println(c.CIDR())
	}
}
