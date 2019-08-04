package cidr

import (
	"net"
)

// IP地址自增
func IncrIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// TODO IP地址自减
func DecrIP(ip net.IP) {
	length := len(ip)
	for i := length - 1; i >= 0; i-- {
		// 最后一字节递减
		ip[length-1]--
		if ip[length-1] > 0 {
			break
		}
		for j := 1; j < length; j++ {
			ip[length-j-1]--
			if ip[length-j-1] > 0 {
				break
			}
			// ip[length-j-1] = 0xFF
		}
	}
}
