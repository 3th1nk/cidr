package cidr_test

import (
	"fmt"
	"testing"

	"github.com/3th1nk/cidr"
)

func TestForEachIP(t *testing.T) {
	c, _ := cidr.ParseCIDR("192.168.1.0/24")
	if err := c.ForEachIP(func(ip string) error {
		fmt.Println(ip)
		return nil
	}); err != nil {
		fmt.Println(err.Error())
	}
}

func TestForEachIPBeginWith(t *testing.T) {
	c, _ := cidr.ParseCIDR("192.168.1.0/24")
	if err := c.ForEachIPBeginWith("192.168.1.230", func(ip string) error {
		fmt.Println(ip)
		return nil
	}); err != nil {
		fmt.Println(err.Error())
	}
}

func TestMask(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	fmt.Println(c1.Mask())

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	fmt.Println(c2.Mask())
}

func TestGateway(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	fmt.Println(c1.Gateway(), c1.Network())

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	fmt.Println(c2.Gateway())
}

func TestBroadcast(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.2.0/24")
	fmt.Println(c1.Broadcast())

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	fmt.Println(c2.Broadcast())
}

func TestIPRange(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	start1, end1 := c1.IPRange()
	fmt.Println(c1.IPCount().String(), start1, end1)

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	start2, end2 := c2.IPRange()
	fmt.Println(c2.IPCount().String(), start2, end2)

	c3, _ := cidr.ParseCIDR("2001:db8::/8")
	start3, end3 := c3.IPRange()
	fmt.Println(c3.IPCount().String(), start3, end3)
}

func TestSubNetting(t *testing.T) {
	c1, _ := cidr.ParseCIDR("192.168.1.0/24")
	cs1, _ := c1.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 256)
	fmt.Println(c1.CIDR(), "按子网数量划分:")
	for _, c := range cs1 {
		fmt.Println(c.CIDR())
	}

	c2, _ := cidr.ParseCIDR("2001:db8::/64")
	cs2, _ := c2.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 4)
	fmt.Println(c2.CIDR(), "按子网数量划分:")
	for _, c := range cs2 {
		fmt.Println(c.CIDR())
	}

	c3, _ := cidr.ParseCIDR("192.168.1.0/24")
	cs3, _ := c3.SubNetting(cidr.SUBNETTING_METHOD_HOST_NUM, 64)
	fmt.Println(c3.CIDR(), "按主机数量划分:")
	for _, c := range cs3 {
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
