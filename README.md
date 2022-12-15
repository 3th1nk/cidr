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
	c, _ := cidr.Parse("192.168.1.0/28")
	fmt.Println("network:", c.Network(), "broadcast:", c.Broadcast(), "mask", c.Mask())

	// ip range
	beginIP, endIP := c.IPRange()
	fmt.Println("ip range:", beginIP, endIP)

	// iterate through each ip
	fmt.Println("ip total:", c.IPCount())
	c.Each(func(ip string) bool {
		fmt.Println("\t", ip)
		return true
	})
	c.EachFrom("192.168.1.10", func(ip string) bool {
		fmt.Println("\t", ip)
		return true
	})

	fmt.Println("subnet plan based on the subnets num:")
	cs, _ := c.SubNetting(cidr.MethodSubnetNum, 4)
	for _, c := range cs {
		fmt.Println("\t", c.CIDR())
	}

	fmt.Println("subnet plan based on the hosts num:")
	cs, _ = c.SubNetting(cidr.MethodHostNum, 4)
	for _, c := range cs {
		fmt.Println("\t", c.CIDR())
	}

	fmt.Println("merge network:")
	c, _ = cidr.SuperNetting([]string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	})
	fmt.Println("\t", c.CIDR())
}
```