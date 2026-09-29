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

// ::ffff:w.x.y.z 前 10 字节清零,10-11 字节置 0xFF,后 4 字节按需填充
func toIPv4Zero(ip net.IP) {
	fillIPBytes(ip, 0, 9, 0)
	fillIPBytes(ip, 10, 11, 0xFF)
	fillIPBytes(ip, 12, 15, 0)
}

func toIPv4Broadcast(ip net.IP) {
	fillIPBytes(ip, 0, 9, 0)
	fillIPBytes(ip, 10, 15, 0xFF)
}

func validIP(ip net.IP) bool {
	return ip != nil && (len(ip) == net.IPv4len || len(ip) == net.IPv6len)
}

// incrBytes increments ip in place, wrapping around to all zeros on overflow
func incrBytes(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// decrBytes decrements ip in place, wrapping around to all 0xFF on underflow
func decrBytes(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] > 0 {
			ip[i]--
			break
		}
		ip[i] = 0xFF
	}
}

// IPIncr ip increase
func IPIncr(ip net.IP) {
	if !validIP(ip) {
		return
	}

	isV4 := ip.To4() != nil
	incrBytes(ip)
	if isV4 && ip.To4() == nil {
		toIPv4Zero(ip)
	}
}

// IPDecr ip decrease
func IPDecr(ip net.IP) {
	if !validIP(ip) {
		return
	}

	isV4 := ip.To4() != nil
	decrBytes(ip)
	if isV4 && ip.To4() == nil {
		toIPv4Broadcast(ip)
	}
}

// IPIncr2 input ip no change
func IPIncr2(ip net.IP) net.IP {
	if !validIP(ip) {
		return nil
	}

	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	IPIncr(ipCopy)
	return ipCopy
}

// IPDecr2 input ip no change
func IPDecr2(ip net.IP) net.IP {
	if !validIP(ip) {
		return nil
	}

	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)
	IPDecr(ipCopy)
	return ipCopy
}

// IPCompare returns an integer comparing two ip
//
//	The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
func IPCompare(a, b net.IP) int {
	return bytes.Compare(a.To16(), b.To16())
}

// IPEqual reports whether a and b are the same IP
func IPEqual(a, b net.IP) bool {
	return IPCompare(a, b) == 0
}

// ip4ToInt converts a v4 ip (4-byte or 4-in-6) to a number
func ip4ToInt(ip net.IP) (int64, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return int64(binary.BigEndian.Uint32(ip4)), true
}

// IP4StrToInt ipv4 ip to number, returns 0 if s is not a valid v4 ip
func IP4StrToInt(s string) int64 {
	n, _ := IP4StrToIntErr(s)
	return n
}

// IP4StrToIntErr ipv4 ip to number, returns an error wrapping ErrInvalidIP if s is not a valid v4 ip
func IP4StrToIntErr(s string) (int64, error) {
	obj := net.ParseIP(s)
	if obj == nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidIP, s)
	}
	n, ok := ip4ToInt(obj)
	if !ok {
		return 0, fmt.Errorf("%w: %v", ErrInvalidIP, s)
	}
	return n, nil
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
		return 0, fmt.Errorf("%w: %v", ErrInvalidIP, src)
	}

	dstIp := net.ParseIP(dst)
	if dstIp == nil || dstIp.To4() == nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidIP, dst)
	}

	srcInt, _ := ip4ToInt(srcIp)
	dstInt, _ := ip4ToInt(dstIp)

	return dstInt - srcInt, nil
}
