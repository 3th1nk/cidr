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
	var got []string
	c.Each(func(ip string) bool {
		got = append(got, ip)
		return true
	})
	assert.Len(t, got, 256)
	assert.Equal(t, "192.168.1.0", got[0])
	assert.Equal(t, "192.168.1.255", got[255])

	// iterator 返回 false 提前退出
	count := 0
	c.Each(func(ip string) bool {
		count++
		return count < 10
	})
	assert.Equal(t, 10, count)

	// 单 IP 网段(/32)
	c32 := ParseNoError("192.168.1.1/32")
	var got32 []string
	c32.Each(func(ip string) bool {
		got32 = append(got32, ip)
		return true
	})
	assert.Equal(t, []string{"192.168.1.1"}, got32)
}

func TestCIDR_EachFrom_OutOfRange(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")

	// beginIP 在网段之前,应返回错误且不迭代
	var count1 int
	err := c.EachFrom("10.0.0.1", func(ip string) bool {
		count1++
		return true
	})
	assert.Error(t, err)
	assert.Equal(t, 0, count1)

	// beginIP 在网段之后,应返回错误且不迭代
	var count2 int
	err = c.EachFrom("192.168.2.1", func(ip string) bool {
		count2++
		return true
	})
	assert.Error(t, err)
	assert.Equal(t, 0, count2)

	// 非法 IP 字符串,应返回错误
	err = c.EachFrom("not-an-ip", func(ip string) bool { return true })
	assert.Error(t, err)

	// 边界:beginIP 为网络地址,应迭代全部 256 个 IP
	var count3 int
	err = c.EachFrom("192.168.1.0", func(ip string) bool {
		count3++
		return true
	})
	assert.NoError(t, err)
	assert.Equal(t, 256, count3)

	// 边界:beginIP 为广播地址,应迭代 1 次
	var count4 int
	err = c.EachFrom("192.168.1.255", func(ip string) bool {
		count4++
		return true
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, count4)
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

func TestCIDR_SubNetting_ExceedLimit(t *testing.T) {
	// 拆分子网数量 2^64、2^32 超过上限,应返回错误而不是空结果
	c1 := ParseNoError("2001:db8::/64")
	cs1, err := c1.SubNetting(MethodSubnetMask, 128)
	assert.Error(t, err)
	assert.Nil(t, cs1)

	c2 := ParseNoError("::/0")
	cs2, err := c2.SubNetting(MethodSubnetMask, 100)
	assert.Error(t, err)
	assert.Nil(t, cs2)

	// 边界:/24 -> /32 拆出 256 个子网,恰好在上限内,应正常返回
	c3 := ParseNoError("192.168.1.0/24")
	cs3, err := c3.SubNetting(MethodSubnetMask, 32)
	assert.NoError(t, err)
	assert.Len(t, cs3, 256)
	assert.Equal(t, "192.168.1.0/32", cs3[0].String())
	assert.Equal(t, "192.168.1.255/32", cs3[255].String())
}

func TestCIDR_SuperNetting_Misaligned(t *testing.T) {
	// 连续但未按父网对齐的段,合并结果应按父掩码对齐
	c, err := SuperNetting([]string{"192.168.0.128/25", "192.168.1.0/25"})
	assert.NoError(t, err)
	assert.Equal(t, "192.168.0.0/24", c.String())
	assert.Equal(t, "192.168.0.0", c.Network().String())
	assert.Equal(t, "192.168.0.255", c.EndIP().String())
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
