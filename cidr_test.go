package cidr

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"net"
	"testing"
)

func TestCIDR_Parse(t *testing.T) {
	// IPv4
	c, err := Parse("192.168.1.0/24")
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())
	assert.Equal(t, int64(256), c.IPCount().Int64())

	// IPv4-compatible	::w.x.y.z or 0:0:0:0:0:0:w.x.y.z
	c, err = Parse("::192.168.1.0/120")
	assert.Nil(t, err)
	assert.Equal(t, "::c0a8:100/120", c.String())
	assert.Equal(t, int64(256), c.IPCount().Int64())

	// IPv6
	c, err = Parse("2001:db8::/32")
	assert.Nil(t, err)
	assert.Equal(t, "2001:db8::/32", c.String())
	assert.Equal(t, big.NewInt(0).Lsh(bigIntOne, 96), c.IPCount())

	// IPv4-mapped	::ffff:w.x.y.z or 0:0:0:0:0:ffff:w.x.y.z
	c, err = Parse("::ffff:192.168.1.0/120")
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())
	assert.Equal(t, int64(256), c.IPCount().Int64())
}

func TestCIDR_Equal(t *testing.T) {
	c, err := Parse("192.168.1.0/24")
	assert.Nil(t, err)
	assert.Equal(t, true, c.Equal("192.168.1.0/24"))
	assert.Equal(t, false, c.Equal("192.168.1.0/25"))

	c, err = Parse("::192.168.1.0/120")
	assert.Nil(t, err)
	assert.Equal(t, true, c.Equal("::192.168.1.0/120"))
	assert.Equal(t, true, c.Equal("::c0a8:100/120"))
	assert.Equal(t, false, c.Equal("::192.168.1.0/24"))
	assert.Equal(t, false, c.Equal("::c0a8:100/121"))

	c, err = Parse("::ffff:192.168.1.0/120")
	assert.Nil(t, err)
	assert.Equal(t, true, c.Equal("::ffff:192.168.1.0/120"))
	assert.Equal(t, true, c.EqualFold("192.168.1.0/24"))
	assert.Equal(t, false, c.Equal("192.168.1.0/25"))
	assert.Equal(t, false, c.Equal("::ffff:192.168.1.0/121"))
}

func TestCIDR_Each(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")
	c.Each(func(ip string) bool {
		t.Log(ip)
		return true
	})
}

func TestCIDR_EachFrom(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")
	_ = c.EachFrom("192.168.1.230", func(ip string) bool {
		t.Log(ip)
		return true
	})
}

func TestCIDR_Mask(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	assert.Equal(t, "ffffff00", c1.Mask().String())
	assert.Equal(t, "255.255.255.0", net.IP(c1.Mask()).String())

	c2 := ParseNoError("2001:db8::/64")
	assert.Equal(t, "ffffffffffffffff0000000000000000", c2.Mask().String())
	assert.Equal(t, "ffff:ffff:ffff:ffff::", net.IP(c2.Mask()).String())
}

func TestCIDR_Broadcast(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")
	assert.Equal(t, "192.168.1.255", c.Broadcast().String())

	c = ParseNoError("2001:db8::/64")
	assert.Equal(t, net.IP(nil), c.Broadcast())

	c = ParseNoError("::ffff:192.168.1.0/120")
	assert.Equal(t, "192.168.1.255", c.Broadcast().String())
}

func TestCIDR_IPRange(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	start1, end1 := c1.IPRange()
	assert.Equal(t, "192.168.1.0", start1.String())
	assert.Equal(t, "192.168.1.255", end1.String())

	c2 := ParseNoError("2001:db8::/64")
	start2, end2 := c2.IPRange()
	assert.Equal(t, "2001:db8::", start2.String())
	assert.Equal(t, "2001:db8::ffff:ffff:ffff:ffff", end2.String())

	c3 := ParseNoError("2001:db8::/8")
	start3, end3 := c3.IPRange()
	assert.Equal(t, "2000::", start3.String())
	assert.Equal(t, "20ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", end3.String())
}

func TestCIDR_SubNetting(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	cs1, _ := c1.SubNetting(MethodSubnetNum, 4)
	t.Log(c1.String(), "按子网数量划分:")
	for _, c := range cs1 {
		t.Log(c.String())
	}

	c2 := ParseNoError("2001:db8::/64")
	cs2, _ := c2.SubNetting(MethodSubnetNum, 4)
	t.Log(c2.String(), "按子网数量划分:")
	for _, c := range cs2 {
		t.Log(c.String())
	}

	c3 := ParseNoError("192.168.1.0/24")
	cs3, _ := c3.SubNetting(MethodHostNum, 64)
	t.Log(c3.String(), "按主机数量划分:")
	for _, c := range cs3 {
		t.Log(c.String())
	}

	c4 := ParseNoError("192.168.1.0/24")
	cs4, err := c4.SubNetting(MethodSubnetMask, 26)
	assert.NoError(t, err)
	t.Log(c4.String(), "按子网掩码划分:")
	for _, c := range cs4 {
		t.Log(c.String())
	}

	c5 := ParseNoError("2001:db8::/64")
	cs5, err := c5.SubNetting(MethodSubnetMask, 66)
	assert.NoError(t, err)
	t.Log(c5.String(), "按子网掩码划分:")
	for _, c := range cs5 {
		t.Log(c.String())
	}
}

func TestCIDR_SuperNetting(t *testing.T) {
	ns4 := []string{
		"192.168.1.0/26",
		"192.168.1.192/26",
		"192.168.1.128/26",
		"192.168.1.64/26",
	}
	c1, err := SuperNetting(ns4)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log(c1.String())

	ns6 := []string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	}
	c2, err := SuperNetting(ns6)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log(c2.String())
}

func TestCIDR_IsPureIPv6(t *testing.T) {
	tests := []struct {
		cidr       string
		expectIPv6 bool
		expectPure bool
	}{
		{"2001:db8::1/128", true, true},         // IPv6
		{"fe80::1/128", true, true},             // IPv6 local address
		{"::1/128", true, true},                 // IPv6 loopback
		{"::/128", true, true},                  // IPv6 unspecified
		{"::192.168.1.1/120", true, false},      // IPv4-compatible
		{"::ffff:192.168.1.1/120", true, false}, // IPv4-mapped
		{"192.168.1.0/24", false, false},        // IPv4
	}

	for _, test := range tests {
		cidr, err := Parse(test.cidr)
		assert.Nil(t, err)
		isIPv6 := cidr.IsIPv6()
		isPure := cidr.IsPureIPv6()
		assert.Equalf(t, test.expectIPv6, isIPv6, test.cidr+": IsIPv6()")
		assert.Equalf(t, test.expectPure, isPure, test.cidr+": IsPureIPv6()")
	}
}
