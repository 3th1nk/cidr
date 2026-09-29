package cidr

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestIPIncr(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		// 边界
		{"v4 zero", net.ParseIP("0.0.0.0"), "0.0.0.1"},
		{"v6 zero", net.ParseIP("::"), "::1"},
		{"v4 max", net.ParseIP("255.255.255.255"), "0.0.0.0"},
		{"v6 max", net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "::"},
		// 4 字节形式的 v4
		{"v4 4-byte", net.IP{0xc0, 0xa8, 0x0, 0xff}, "192.168.1.0"},
		// 非法输入
		{"nil", nil, "<nil>"},
		{"invalid len", net.IP{1, 2}, "?0102"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			IPIncr(test.ip)
			assert.Equal(t, test.expected, test.ip.String())
		})
	}
}

func TestIPDecr(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		// 边界
		{"v4 max", net.ParseIP("255.255.255.255"), "255.255.255.254"},
		{"v6 max", net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
		{"v4 zero", net.ParseIP("0.0.0.0"), "255.255.255.255"},
		{"v6 zero", net.ParseIP("::"), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		// 4 字节形式的 v4
		{"v4 4-byte", net.IP{0xc0, 0xa8, 0x1, 0x0}, "192.168.0.255"},
		// 非法输入
		{"nil", nil, "<nil>"},
		{"invalid len", net.IP{1, 2}, "?0102"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			IPDecr(test.ip)
			assert.Equal(t, test.expected, test.ip.String())
		})
	}
}

func TestIPIncr2(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		// 边界
		{"v4 max", net.ParseIP("255.255.255.255"), "0.0.0.0"},
		{"v6 max", net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "::"},
		{"v4 zero", net.ParseIP("0.0.0.0"), "0.0.0.1"},
		{"v6 zero", net.ParseIP("::"), "::1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := test.ip.String()
			result := IPIncr2(test.ip)
			assert.Equal(t, test.expected, result.String())
			// 输入不被修改
			assert.Equal(t, src, test.ip.String())
		})
	}

	// 非法输入返回 nil
	assert.Nil(t, IPIncr2(nil))
	assert.Nil(t, IPIncr2(net.IP{1, 2}))
}

func TestIPDecr2(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		// 边界
		{"v4 zero", net.ParseIP("0.0.0.0"), "255.255.255.255"},
		{"v6 zero", net.ParseIP("::"), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"v4 max", net.ParseIP("255.255.255.255"), "255.255.255.254"},
		{"v6 max", net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := test.ip.String()
			result := IPDecr2(test.ip)
			assert.Equal(t, test.expected, result.String())
			// 输入不被修改
			assert.Equal(t, src, test.ip.String())
		})
	}

	// 非法输入返回 nil
	assert.Nil(t, IPDecr2(nil))
	assert.Nil(t, IPDecr2(net.IP{1, 2}))
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
