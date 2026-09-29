package cidr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	// 非法输入返回 false
	assert.Equal(t, false, c.Equal("bad"))
}

func TestCIDR_EqualNormalized(t *testing.T) {
	c, err := Parse("::ffff:192.168.1.0/120")
	assert.Nil(t, err)
	// 与 EqualFold 行为一致:归一化后比较,含 IPv4-mapped 等价
	assert.Equal(t, c.EqualFold("192.168.1.0/24"), c.EqualNormalized("192.168.1.0/24"))
	assert.Equal(t, true, c.EqualNormalized("192.168.1.0/24"))
	assert.Equal(t, false, c.EqualNormalized("192.168.1.0/25"))
	assert.Equal(t, false, c.EqualNormalized("bad"))
}

func TestCIDR_IsIPv4(t *testing.T) {
	assert.Equal(t, true, MustParse("192.168.1.0/24").IsIPv4())
	assert.Equal(t, false, MustParse("2001:db8::/32").IsIPv4())
	// IPv4-mapped 按 IPv6 处理(见 IsIPv6 文档)
	assert.Equal(t, false, MustParse("::ffff:192.168.1.0/120").IsIPv4())
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

func TestCIDR_Contains(t *testing.T) {
	tests := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.0", true},         // 网络地址
		{"192.168.1.0/24", "192.168.1.255", true},       // 广播地址
		{"192.168.1.0/24", "192.168.2.1", false},        // 范围外
		{"2001:db8::/32", "2001:db8::1", true},          // IPv6
		{"2001:db8::/32", "2001:db9::1", false},         // IPv6 范围外
		{"::ffff:192.168.1.0/120", "192.168.1.5", true}, // v4-mapped 等价
		{"192.168.1.0/24", "bad", false},                // 非法 IP
	}

	for _, tt := range tests {
		assert.Equalf(t, tt.want, MustParse(tt.cidr).Contains(tt.ip), "%v contains %v", tt.cidr, tt.ip)
	}
}

func TestCIDR_Overlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.0/25", true},         // 包含
		{"192.168.1.0/25", "192.168.1.0/24", true},         // 被包含(对称)
		{"192.168.1.0/25", "192.168.1.128/25", false},      // 相邻不重叠
		{"192.168.1.0/24", "192.168.2.0/24", false},        // 分离
		{"0.0.0.0/0", "192.168.1.0/24", true},              // v4 全网
		{"2001:db8::/32", "2001:db8::1/128", true},         // IPv6
		{"2001:db8::/32", "2001:db9::/32", false},          // IPv6 分离
		{"2001:db8::/32", "192.168.1.0/24", false},         // 跨族(纯 v6 与 v4)
		{"::ffff:192.168.1.0/120", "192.168.1.0/24", true}, // v4-mapped 与 v4 等价
	}

	for _, tt := range tests {
		assert.Equalf(t, tt.want, MustParse(tt.a).Overlaps(MustParse(tt.b)), "%v overlaps %v", tt.a, tt.b)
	}
}

func TestCIDR_IsSubnetOf(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"192.168.1.0/24", "192.168.0.0/16", true},
		{"192.168.0.0/16", "192.168.1.0/24", false},
		{"192.168.1.0/24", "192.168.1.0/24", true}, // 相等视为子网
		{"192.168.1.0/24", "0.0.0.0/0", true},
		{"2001:db8::/32", "2001::/16", true},
		{"192.168.1.0/24", "2001:db8::/32", false},         // 跨族
		{"::ffff:192.168.1.0/120", "192.168.1.0/24", true}, // v4-mapped 子网于 v4
	}

	for _, tt := range tests {
		assert.Equalf(t, tt.want, MustParse(tt.a).IsSubnetOf(MustParse(tt.b)), "%v is subnet of %v", tt.a, tt.b)
	}
}

func TestCIDR_IsSupernetOf(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"192.168.0.0/16", "192.168.1.0/24", true},
		{"192.168.1.0/24", "192.168.0.0/16", false},
		{"192.168.1.0/24", "192.168.1.0/24", true}, // 相等视为父网
		{"0.0.0.0/0", "192.168.1.0/24", true},
	}

	for _, tt := range tests {
		assert.Equalf(t, tt.want, MustParse(tt.a).IsSupernetOf(MustParse(tt.b)), "%v is supernet of %v", tt.a, tt.b)
	}
}
