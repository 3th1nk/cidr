package cidr

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestIPIncr(t *testing.T) {
	tests := []struct {
		ip    net.IP
		valid bool
	}{
		{net.ParseIP("0.0.0.0"), true},
		{net.ParseIP("::"), true},
		// 边界
		{net.ParseIP("255.255.255.255"), true},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true},
		// 非法输入
		{nil, false},
		{[]byte{1, 2}, false},
	}

	for _, test := range tests {
		srcIP := make(net.IP, len(test.ip))
		copy(srcIP, test.ip)
		IPIncr(test.ip)
		fmt.Printf("IPIncr Input: %v -> Output: %v\n", srcIP, test.ip)
	}
}

func TestIPDecr(t *testing.T) {
	tests := []struct {
		ip    net.IP
		valid bool
	}{
		{net.ParseIP("255.255.255.255"), true},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true},
		// 边界
		{net.ParseIP("0.0.0.0"), true},
		{net.ParseIP("::"), true},
		// 非法输入
		{nil, false},
		{[]byte{1, 2}, false},
	}

	for _, test := range tests {
		srcIP := make(net.IP, len(test.ip))
		copy(srcIP, test.ip)
		IPDecr(test.ip)
		fmt.Printf("IPDecr Input: %v -> Output: %v\n", srcIP, test.ip)
	}
}

func TestIPIncr2(t *testing.T) {
	tests := []struct {
		ip    net.IP
		valid bool
	}{
		{net.ParseIP("255.255.255.255"), true},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true},
		// 边界
		{net.ParseIP("0.0.0.0"), true},
		{net.ParseIP("::"), true},
		// 非法输入
		{nil, false},
		{[]byte{1, 2}, false},
	}

	for _, test := range tests {
		result := IPIncr2(test.ip)
		fmt.Printf("IPIncr2 Input: %v -> Output: %v\n", test.ip, result)
	}
}

func TestIPDecr2(t *testing.T) {
	tests := []struct {
		ip    net.IP
		valid bool
	}{
		{net.ParseIP("255.255.255.255"), true},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true},
		// 边界
		{net.ParseIP("0.0.0.0"), true},
		{net.ParseIP("::"), true},
		// 非法输入
		{nil, false},
		{[]byte{1, 2}, false},
	}

	for _, test := range tests {
		result := IPDecr2(test.ip)
		fmt.Printf("IPDecr2 Input: %v -> Output: %v\n", test.ip, result)
	}
}

func TestIPCompare(t *testing.T) {
	assert.Equal(t, -1, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.20")))
	assert.Equal(t, -1, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.10")))
	assert.Equal(t, 0, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.2")))
	assert.Equal(t, -1, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.3")))
	assert.Equal(t, 1, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1")))
	assert.Equal(t, -1, IPCompare(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::1")))
	assert.Equal(t, 1, IPCompare(net.ParseIP("2001:db8::"), net.ParseIP("192.168.1.1")))
}

func TestIPEqual(t *testing.T) {
	assert.Equal(t, false, IPEqual(net.ParseIP("192.168.1.0"), net.ParseIP("192.168.1.1")))
	assert.Equal(t, true, IPEqual(net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.1")))
	assert.Equal(t, false, IPEqual(net.ParseIP("fd00::"), net.ParseIP("fd00::1")))
	assert.Equal(t, true, IPEqual(net.ParseIP("fd00::"), net.ParseIP("fd00::")))
}

func TestIP4StrToInt(t *testing.T) {
	assert.Equal(t, int64(3232235777), IP4StrToInt("192.168.1.1"))
	assert.Equal(t, int64(4294967295), IP4StrToInt("255.255.255.255"))
	assert.Equal(t, int64(0), IP4StrToInt("0.0.0.0"))
}

func TestIP4IntToStr(t *testing.T) {
	assert.Equal(t, "192.168.1.1", IP4IntToStr(3232235777))
	assert.Equal(t, "255.255.255.255", IP4IntToStr(4294967295))
	assert.Equal(t, "0.0.0.0", IP4IntToStr(0))
}

func TestIP4Distance(t *testing.T) {
	n, _ := IP4Distance("192.168.1.0", "192.168.1.1")
	assert.Equal(t, int64(1), n)

	n, _ = IP4Distance("192.168.1.1", "192.168.1.0")
	assert.Equal(t, int64(-1), n)

	n, _ = IP4Distance("192.168.0.255", "192.168.1.255")
	assert.Equal(t, int64(256), n)
}
