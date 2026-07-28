# CIDR

## Características
* fácil de iterar a través de cada ip en el segmento
* verificar segmento ipv4 o ipv6
* verificar si el segmento contiene una ip
* ordenación, división y fusión de segmentos
* incremento y decremento de ip
* comparación de ips

## Ejemplo de Código
```
package main

import (
	"fmt"
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

	fmt.Println("merge network:")
	c, _ = cidr.SuperNetting([]string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	})
	fmt.Println("\t", c.String())
}
```
