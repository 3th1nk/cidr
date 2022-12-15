package cidr

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPIncr ip increase
func IPIncr(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// IPDecr ip decrease
func IPDecr(ip net.IP) {
	length := len(ip)
	for i := length - 1; i >= 0; i-- {
		ip[length-1]--
		if ip[length-1] < 0xFF {
			break
		}
		for j := 1; j < length; j++ {
			ip[length-j-1]--
			if ip[length-j-1] < 0xFF {
				return
			}
		}
	}
}

// IPCompare returns an integer comparing two ip
// 	The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
func IPCompare(a, b net.IP) int {
	return bytes.Compare(a, b)
}

// IPEqual reports whether a and b are the same IP
func IPEqual(a, b net.IP) bool {
	return bytes.Equal(a, b)
}

// IP4StrToInt ipv4 ip to number
func IP4StrToInt(s string) int64 {
	obj := net.ParseIP(s)
	if obj == nil || len(obj.To4()) != net.IPv4len {
		return 0
	}

	bits := strings.Split(obj.String(), ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	return sum
}

// IP4IntToStr number to ipv4 ip
func IP4IntToStr(n int64) string {
	var b [4]byte
	b[0] = byte(n & 0xFF)
	b[1] = byte((n >> 8) & 0xFF)
	b[2] = byte((n >> 16) & 0xFF)
	b[3] = byte((n >> 24) & 0xFF)
	return net.IPv4(b[3], b[2], b[1], b[0]).String()
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

	return IP4StrToInt(dstIp.String()) - IP4StrToInt(srcIp.String()), nil
}
