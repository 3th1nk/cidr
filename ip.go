package cidr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

func fillIPBytes(ip net.IP, start, end int, fill byte) {
	if start < 0 {
		start = 0
	}
	if end >= len(ip) {
		end = len(ip) - 1
	}
	if start > end {
		return
	}
	for i := start; i <= end; i++ {
		ip[i] = fill
	}
}

func toIPv4Zero(ip net.IP) {
	fillIPBytes(ip, 0, 10, 0)
	fillIPBytes(ip, 10, 11, 0xFF)
	fillIPBytes(ip, 11, 15, 0)
}

func toIPv4Broadcast(ip net.IP) {
	fillIPBytes(ip, 0, 10, 0)
	fillIPBytes(ip, 10, 15, 0xFF)
}

// IPIncr ip increase
func IPIncr(ip net.IP) {
	if ip == nil || (len(ip) != net.IPv4len && len(ip) != net.IPv6len) {
		return
	}

	isV4 := ip.To4() != nil
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}

	if isV4 && ip.To4() == nil {
		toIPv4Zero(ip)
	}
}

// IPDecr ip decrease
func IPDecr(ip net.IP) {
	if ip == nil || (len(ip) != net.IPv4len && len(ip) != net.IPv6len) {
		return
	}

	isV4 := ip.To4() != nil
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] > 0 {
			ip[i]--
			break
		} else {
			ip[i] = 0xFF
		}
	}

	if isV4 && ip.To4() == nil {
		toIPv4Broadcast(ip)
	}
}

// IPIncr2 input ip no change
func IPIncr2(ip net.IP) net.IP {
	if ip == nil || (len(ip) != net.IPv4len && len(ip) != net.IPv6len) {
		return nil
	}

	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)

	for i := len(ipCopy) - 1; i >= 0; i-- {
		ipCopy[i]++
		if ipCopy[i] > 0 {
			break
		}
	}

	if ip.To4() != nil && ipCopy.To4() == nil {
		toIPv4Zero(ipCopy)
	}
	return ipCopy
}

// IPDecr2 input ip no change
func IPDecr2(ip net.IP) net.IP {
	if ip == nil || (len(ip) != net.IPv4len && len(ip) != net.IPv6len) {
		return nil
	}

	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)

	for i := len(ipCopy) - 1; i >= 0; i-- {
		if ipCopy[i] > 0 {
			ipCopy[i]--
			break
		} else {
			ipCopy[i] = 0xFF
		}
	}

	if ip.To4() != nil && ipCopy.To4() == nil {
		toIPv4Broadcast(ipCopy)
	}
	return ipCopy
}

// IPCompare returns an integer comparing two ip
// 	The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
func IPCompare(a, b net.IP) int {
	return bytes.Compare(a.To16(), b.To16())
}

// IPEqual reports whether a and b are the same IP
func IPEqual(a, b net.IP) bool {
	return IPCompare(a, b) == 0
}

// IP4StrToInt ipv4 ip to number
func IP4StrToInt(s string) int64 {
	obj := net.ParseIP(s)
	if obj == nil || obj.To4() == nil {
		return 0
	}
	ip4 := obj.To4()
	return int64(binary.BigEndian.Uint32(ip4))
}

// IP4IntToStr number to ipv4 ip
func IP4IntToStr(n int64) string {
	if n < 0 || n > 0xFFFFFFFF {
		return ""
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	return net.IP(buf).String()
}

// IP4Distance return the number of ip between two v4 ip
func IP4Distance(src, dst string) (int64, error) {
	srcIp := net.ParseIP(src)
	if srcIp == nil || srcIp.To4() == nil {
		return 0, fmt.Errorf("invalid v4 ip: %v", src)
	}

	dstIp := net.ParseIP(dst)
	if dstIp == nil || dstIp.To4() == nil {
		return 0, fmt.Errorf("invalid v4 ip: %v", dst)
	}

	srcInt := IP4StrToInt(srcIp.String())
	dstInt := IP4StrToInt(dstIp.String())

	return dstInt - srcInt, nil
}
