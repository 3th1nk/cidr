package cidr

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestIPIncrAndDecr(t *testing.T) {
	ip4Obj := net.ParseIP("192.168.1.1")
	IPDecr(ip4Obj)
	assert.Equal(t, "192.168.1.0", ip4Obj.String())
	IPDecr(ip4Obj)
	assert.Equal(t, "192.168.0.255", ip4Obj.String())
	IPIncr(ip4Obj)
	assert.Equal(t, "192.168.1.0", ip4Obj.String())

	ip6Obj := net.ParseIP("2001:db8::")
	IPDecr(ip6Obj)
	assert.Equal(t, "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", ip6Obj.String())
	IPIncr(ip6Obj)
	assert.Equal(t, "2001:db8::", ip6Obj.String())
	IPIncr(ip6Obj)
	assert.Equal(t, "2001:db8::1", ip6Obj.String())
}

func TestIPCompare(t *testing.T) {
	assert.Equal(t, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.20")), -1)
	assert.Equal(t, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.10")), -1)
	assert.Equal(t, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.2")), 0)
	assert.Equal(t, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.3")), -1)
	assert.Equal(t, IPCompare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1")), 1)
	assert.Equal(t, IPCompare(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::1")), -1)
	assert.Equal(t, IPCompare(net.ParseIP("2001:db8::"), net.ParseIP("192.168.1.1")), -1)
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
