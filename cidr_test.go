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

func TestSubNetting(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	cs1, _ := c1.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 4)
	fmt.Println("IPv4子网划分:")
	for _, c := range cs1 {
		fmt.Println(c.CIDR())
	}

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	cs2, _ := c2.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 4)
	fmt.Println("IPv6子网划分:")
	for _, c := range cs2 {
		fmt.Println(c.CIDR())
	}
}

func TestSuperNetting(t *testing.T) {
	ns4 := []string{
		"192.168.1.0/26",
		"192.168.1.192/26",
		"192.168.1.128/26",
		"192.168.1.64/26",
	}
	c1, err := cidr.SuperNetting(ns4)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(c1.CIDR())

	ns6 := []string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	}
	c2, err := cidr.SuperNetting(ns6)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(c2.CIDR())
}
