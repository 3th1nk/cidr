# CIDR

## Features
* easy to iterate through each ip in segment
* check ipv4 or ipv6 segment
* check whether segment contain ip
* segments sort, split, merge
* relation checks: `Overlaps`, `IsSubnetOf`, `IsSupernetOf`
* set operations: `CollapseCIDRs` (normalize & merge), `RangeToCIDRs`,
  `SpanningCIDR`, `Exclude`
* usable hosts: `HostCount`, `NthHost`
* masks: `DottedMask`, `WildcardMask`, `MaskToPrefix`
* ip incr & decr
* ip compare
* errors checkable via `errors.Is`

## Code Example
```go
package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/3th1nk/cidr"
)

func main() {
	// parses a network segment as a CIDR
	c, _ := cidr.Parse("192.168.1.0/28")
	fmt.Println("network:", c.Network(), "broadcast:", c.Broadcast(), "mask", net.IP(c.Mask()))

	// ip range
	fmt.Println("ip range:", c.StartIP(), c.EndIP())

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
		fmt.Println("\t", c.String())
	}

	fmt.Println("subnet plan based on the hosts num:")
	cs, _ = c.SubNetting(cidr.MethodHostNum, 4)
	for _, c := range cs {
		fmt.Println("\t", c.String())
	}

	fmt.Println("subnet plan based on the subnet mask:")
	cs, _ = c.SubNetting(cidr.MethodSubnetMask, 30)
	for _, c := range cs {
		fmt.Println("\t", c.String())
	}

	fmt.Println("merge network:")
	c, _ = cidr.SuperNetting([]string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	})
	fmt.Println("\t", c.String())

	// errors can be checked with errors.Is
	_, err := c.SubNetting(cidr.MethodSubnetNum, 3)
	if errors.Is(err, cidr.ErrInvalidNum) {
		fmt.Println("invalid num:", err)
	}
}
```

## More

```go
a := cidr.MustParse("192.168.1.0/24")
b := cidr.MustParse("192.168.0.0/16")

// relation checks
a.Overlaps(b)    // true
a.IsSubnetOf(b)  // true
b.IsSupernetOf(a) // true

// normalize & merge an arbitrary list (overlaps and gaps are fine)
merged := cidr.CollapseCIDRs([]*cidr.CIDR{
	cidr.MustParse("192.168.1.0/25"),
	cidr.MustParse("192.168.1.128/25"),
	cidr.MustParse("10.0.0.0/8"),
})
// ["10.0.0.0/8", "192.168.1.0/24"]

// convert an IP range into the minimal list of CIDRs
cidrs, _ := cidr.RangeToCIDRs("192.168.1.1", "192.168.1.10")

// the smallest CIDR covering a set
c, _ := cidr.SpanningCIDR([]*cidr.CIDR{a, b})

// carve a subnet out and keep the rest
rest, _ := a.Exclude(cidr.MustParse("192.168.1.64/26"))

// usable hosts
n := a.HostCount()   // 254
h, _ := a.NthHost(0) // 192.168.1.1

// masks
a.DottedMask()   // "255.255.255.0"
a.WildcardMask() // "0.0.0.255" (Cisco ACL)
cidr.MaskToPrefix("255.255.255.0") // 24

// interop with the standard library net/netip (Go 1.18+)
p, _ := a.AsNetip() // netip.Prefix

// JSON: CIDR values marshal to a string like "192.168.1.0/24"
```
