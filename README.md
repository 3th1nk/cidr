# CIDR

## Features
* easy to iterate through each ip in segment
* check ipv4 or ipv6 segment
* check whether segment contain ip
* segments sort、split、merge
* ip incr & decr
* ip compare

## Code Example
```
package main

import (
	"fmt"
	"github.com/3th1nk/cidr"
)

func main() {
	// parses a network segment as a CIDR
	c, _ := cidr.ParseCIDR("192.168.1.0/28")
	fmt.Println("network:", c.Network())
	fmt.Println("broadcast:", c.Broadcast())

	// ip range
	beginIP, endIP := c.IPRange()
	fmt.Println("ip range:", beginIP, endIP)

	// iterate through each ip
	fmt.Println("ip total:", c.IPCount())
	c.ForEachIP(func(ip string) error {
		fmt.Println(ip)
		return nil
	})

	// split network segment based on the subnets number
	cs, _ := c.SubNetting(cidr.SUBNETTING_METHOD_SUBNET_NUM, 4)
	for _, c := range cs {
		fmt.Println("split network", c.CIDR())
	}

	// split network segment based on the hosts number in the subnet
	cs, _ = c.SubNetting(cidr.SUBNETTING_METHOD_HOST_NUM, 4)
	for _, c := range cs {
		fmt.Println("split2 network", c.CIDR())
	}

	// merge network segments
	c, _ = cidr.SuperNetting([]string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	})
	fmt.Println("merge network", c.CIDR())
}
```