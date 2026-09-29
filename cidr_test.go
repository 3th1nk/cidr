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

	// 非法输入返回 false
	assert.Equal(t, false, c.Equal("bad"))
}

func TestCIDR_Each(t *testing.T) {
	c := MustParse("192.168.1.0/24")
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
	c32 := MustParse("192.168.1.1/32")
	var got32 []string
	c32.Each(func(ip string) bool {
		got32 = append(got32, ip)
		return true
	})
	assert.Equal(t, []string{"192.168.1.1"}, got32)
}

func TestCIDR_EachFrom_OutOfRange(t *testing.T) {
	c := MustParse("192.168.1.0/24")

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

	// 错误类型可通过 errors.Is 判断
	assert.ErrorIs(t, c.EachFrom("bad", func(ip string) bool { return true }), ErrInvalidIP)
	assert.ErrorIs(t, c.EachFrom("10.0.0.1", func(ip string) bool { return true }), ErrIPNotInCIDR)

	// 网段中间起始:应从起始 IP 迭代到广播地址(230~255 共 26 个)
	var count5 int
	err = c.EachFrom("192.168.1.230", func(ip string) bool {
		count5++
		return true
	})
	assert.NoError(t, err)
	assert.Equal(t, 26, count5)

	// iterator 返回 false 提前退出
	count5 = 0
	_ = c.EachFrom("192.168.1.230", func(ip string) bool {
		count5++
		return count5 < 5
	})
	assert.Equal(t, 5, count5)
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

func TestCIDR_IsIPv4(t *testing.T) {
	assert.Equal(t, true, MustParse("192.168.1.0/24").IsIPv4())
	assert.Equal(t, false, MustParse("2001:db8::/32").IsIPv4())
	// IPv4-mapped 按 IPv6 处理(见 IsIPv6 文档)
	assert.Equal(t, false, MustParse("::ffff:192.168.1.0/120").IsIPv4())
}

func TestCIDR_IPAndCIDRGetter(t *testing.T) {
	// IP() 返回未按掩码修正的前缀
	c, err := Parse("192.168.1.10/24")
	assert.Nil(t, err)
	assert.Equal(t, "192.168.1.10", c.IP().String())
	// Network() 返回修正后的网络地址
	assert.Equal(t, "192.168.1.0", c.Network().String())
	// CIDR() 返回归一化的 *net.IPNet
	assert.Equal(t, "192.168.1.0/24", c.CIDR().String())
}

func TestCIDR_Mask(t *testing.T) {
	c1 := MustParse("192.168.1.0/24")
	assert.Equal(t, "ffffff00", c1.Mask().String())
	assert.Equal(t, "255.255.255.0", net.IP(c1.Mask()).String())

	c2 := MustParse("2001:db8::/64")
	assert.Equal(t, "ffffffffffffffff0000000000000000", c2.Mask().String())
	assert.Equal(t, "ffff:ffff:ffff:ffff::", net.IP(c2.Mask()).String())
}

func TestCIDR_Broadcast(t *testing.T) {
	c := MustParse("192.168.1.0/24")
	assert.Equal(t, "192.168.1.255", c.Broadcast().String())

	c = MustParse("2001:db8::/64")
	assert.Equal(t, net.IP(nil), c.Broadcast())

	c = MustParse("::ffff:192.168.1.0/120")
	assert.Equal(t, "192.168.1.255", c.Broadcast().String())
}

func TestCIDR_IPRange(t *testing.T) {
	c1 := MustParse("192.168.1.0/24")
	start1, end1 := c1.IPRange()
	assert.Equal(t, "192.168.1.0", start1.String())
	assert.Equal(t, "192.168.1.255", end1.String())

	c2 := MustParse("2001:db8::/64")
	start2, end2 := c2.IPRange()
	assert.Equal(t, "2001:db8::", start2.String())
	assert.Equal(t, "2001:db8::ffff:ffff:ffff:ffff", end2.String())

	c3 := MustParse("2001:db8::/8")
	start3, end3 := c3.IPRange()
	assert.Equal(t, "2000::", start3.String())
	assert.Equal(t, "20ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", end3.String())
}

func TestCIDR_SubNetting(t *testing.T) {
	v4Subnets := []string{"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26", "192.168.1.192/26"}
	v6Subnets := []string{"2001:db8::/66", "2001:db8:0:0:4000::/66", "2001:db8:0:0:8000::/66", "2001:db8:0:0:c000::/66"}

	tests := []struct {
		name    string
		cidr    string
		method  SubNettingMethod
		num     int
		want    []string
		wantErr error
	}{
		{name: "v4 by subnet num", cidr: "192.168.1.0/24", method: MethodSubnetNum, num: 4, want: v4Subnets},
		{name: "v6 by subnet num", cidr: "2001:db8::/64", method: MethodSubnetNum, num: 4, want: v6Subnets},
		{name: "v4 by host num", cidr: "192.168.1.0/24", method: MethodHostNum, num: 64, want: v4Subnets},
		{name: "v4 by subnet mask", cidr: "192.168.1.0/24", method: MethodSubnetMask, num: 26, want: v4Subnets},
		{name: "v6 by subnet mask", cidr: "2001:db8::/64", method: MethodSubnetMask, num: 66, want: v6Subnets},
		// 非法输入
		{name: "num not power of 2", cidr: "192.168.1.0/24", method: MethodSubnetNum, num: 3, wantErr: ErrInvalidNum},
		{name: "num zero", cidr: "192.168.1.0/24", method: MethodSubnetNum, num: 0, wantErr: ErrInvalidNum},
		{name: "num negative", cidr: "192.168.1.0/24", method: MethodSubnetNum, num: -1, wantErr: ErrInvalidNum},
		{name: "host num not power of 2", cidr: "192.168.1.0/24", method: MethodHostNum, num: 3, wantErr: ErrInvalidNum},
		{name: "unsupported method", cidr: "192.168.1.0/24", method: SubNettingMethod(99), num: 4, wantErr: ErrUnsupportedMethod},
		{name: "mask less than parent", cidr: "192.168.1.0/24", method: MethodSubnetMask, num: 15, wantErr: ErrNumOutOfRange},
		{name: "mask greater than bits", cidr: "192.168.1.0/24", method: MethodSubnetMask, num: 33, wantErr: ErrNumOutOfRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := MustParse(tt.cidr).SubNetting(tt.method, tt.num)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, cs)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, cidrStrings(cs))
		})
	}
}

func TestCIDR_SuperNetting(t *testing.T) {
	tests := []struct {
		name    string
		ns      []string
		want    string
		wantErr error
	}{
		{
			name: "v4",
			ns:   []string{"192.168.1.0/26", "192.168.1.192/26", "192.168.1.128/26", "192.168.1.64/26"},
			want: "192.168.1.0/24",
		},
		{
			name: "v6",
			ns:   []string{"2001:db8::/66", "2001:db8:0:0:8000::/66", "2001:db8:0:0:4000::/66", "2001:db8:0:0:c000::/66"},
			want: "2001:db8::/64",
		},
		// 非法输入
		{name: "empty", ns: nil, wantErr: ErrInvalidNum},
		{name: "length not power of 2", ns: []string{"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26"}, wantErr: ErrInvalidNum},
		{name: "invalid cidr", ns: []string{"192.168.1.0/26", "bad"}, wantErr: ErrInvalidCIDR},
		{name: "different mask", ns: []string{"192.168.1.0/26", "192.168.1.64/25"}, wantErr: ErrNotSameMask},
		{name: "not contiguous", ns: []string{"192.168.1.0/26", "192.168.1.192/26"}, wantErr: ErrNotContiguous},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := SuperNetting(tt.ns)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, c)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, c.String())
		})
	}
}

// cidrStrings returns the string representations of the CIDRs
func cidrStrings(cs []*CIDR) []string {
	ss := make([]string, 0, len(cs))
	for _, c := range cs {
		ss = append(ss, c.String())
	}
	return ss
}

func TestCIDR_SubNetting_ExceedLimit(t *testing.T) {
	// 拆分子网数量 2^64、2^32 超过上限,应返回错误而不是空结果
	c1 := MustParse("2001:db8::/64")
	cs1, err := c1.SubNetting(MethodSubnetMask, 128)
	assert.Error(t, err)
	assert.Nil(t, cs1)

	c2 := MustParse("::/0")
	cs2, err := c2.SubNetting(MethodSubnetMask, 100)
	assert.Error(t, err)
	assert.Nil(t, cs2)

	// 边界:/24 -> /32 拆出 256 个子网,恰好在上限内,应正常返回
	c3 := MustParse("192.168.1.0/24")
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

func TestCIDR_ParseLoose(t *testing.T) {
	// 裸 IP 视为单主机网段
	c, err := ParseLoose("192.168.1.10")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.10/32", c.String())

	c, err = ParseLoose("2001:db8::1")
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::1/128", c.String())

	// host bits 非零,归一化为网络地址,前缀保留在 IP() 中
	c, err = ParseLoose("192.168.1.10/24")
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())
	assert.Equal(t, "192.168.1.10", c.IP().String())

	// 非法输入
	c, err = ParseLoose("bad")
	assert.ErrorIs(t, err, ErrInvalidCIDR)
	assert.Nil(t, c)

	c, err = ParseLoose("192.168.1.0/33")
	assert.Error(t, err)
	assert.Nil(t, c)
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

func TestCIDR_HostCount(t *testing.T) {
	// IPv4 减去网络地址与广播地址
	assert.Equal(t, int64(254), MustParse("192.168.1.0/24").HostCount().Int64())
	assert.Equal(t, int64(126), MustParse("192.168.1.0/25").HostCount().Int64())
	assert.Equal(t, int64(2), MustParse("192.168.1.0/30").HostCount().Int64())
	// RFC 3021:/31 点对点链路两个地址都可用;/32 单主机
	assert.Equal(t, int64(2), MustParse("192.168.1.0/31").HostCount().Int64())
	assert.Equal(t, int64(1), MustParse("192.168.1.1/32").HostCount().Int64())
	// IPv6 全量计数,不减
	assert.Equal(t, big.NewInt(0).Lsh(bigIntOne, 64), MustParse("2001:db8::/64").HostCount())
	assert.Equal(t, int64(1), MustParse("2001:db8::1/128").HostCount().Int64())
	// v4-mapped 段(128 位掩码)按 IPv6 语义全量计数
	assert.Equal(t, int64(256), MustParse("::ffff:192.168.1.0/120").HostCount().Int64())
}

func TestCIDR_NthHost(t *testing.T) {
	// IPv4 常规段:0 号主机为第一个可用地址(跳过网络地址)
	c := MustParse("192.168.1.0/24")
	ip, err := c.NthHost(0)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip.String())

	ip, err = c.NthHost(253)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.254", ip.String())

	// 越界:可用主机共 254 个
	_, err = c.NthHost(254)
	assert.ErrorIs(t, err, ErrNumOutOfRange)

	// /31:两个地址都可用,不跳过
	c31 := MustParse("192.168.1.0/31")
	ip, err = c31.NthHost(0)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0", ip.String())
	ip, err = c31.NthHost(1)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip.String())

	// /32:仅自身
	ip, err = MustParse("192.168.1.1/32").NthHost(0)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip.String())

	// IPv6:从网络地址开始全量计数
	ip, err = MustParse("2001:db8::/64").NthHost(0)
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::", ip.String())
	ip, err = MustParse("2001:db8::/64").NthHost(1)
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::1", ip.String())

	// 负数
	_, err = c.NthHost(-1)
	assert.ErrorIs(t, err, ErrNumOutOfRange)
}

func TestCIDR_DottedMask(t *testing.T) {
	assert.Equal(t, "255.255.255.0", MustParse("192.168.1.0/24").DottedMask())
	assert.Equal(t, "255.255.255.255", MustParse("192.168.1.1/32").DottedMask())
	assert.Equal(t, "ffff:ffff::", MustParse("2001:db8::/32").DottedMask())
	assert.Equal(t, "ffff:ffff:ffff:ffff::", MustParse("2001:db8::/64").DottedMask())
}

func TestCIDR_WildcardMask(t *testing.T) {
	assert.Equal(t, "0.0.0.255", MustParse("192.168.1.0/24").WildcardMask())
	assert.Equal(t, "255.255.255.255", MustParse("0.0.0.0/0").WildcardMask())
	assert.Equal(t, "0.0.0.0", MustParse("192.168.1.1/32").WildcardMask())
	assert.Equal(t, "0.0.0.127", MustParse("192.168.1.0/25").WildcardMask())
	// v4-mapped 取低 32 位
	assert.Equal(t, "0.0.0.255", MustParse("::ffff:192.168.1.0/120").WildcardMask())
	// 纯 IPv6 不支持
	assert.Equal(t, "", MustParse("2001:db8::/64").WildcardMask())
}

func TestMaskToPrefix(t *testing.T) {
	tests := []struct {
		mask    string
		want    int
		wantErr error
	}{
		{"0.0.0.0", 0, nil},
		{"128.0.0.0", 1, nil},
		{"255.255.255.128", 25, nil},
		{"255.255.255.0", 24, nil},
		{"255.255.255.255", 32, nil},
		{"ffff:ffff::", 32, nil},
		{"ffff:ffff:ffff:ffff::", 64, nil},
		// 非法输入
		{"255.0.255.0", 0, ErrInvalidMask}, // 不连续
		{"1.2.3.4", 0, ErrInvalidMask},     // 非掩码
		{"bad", 0, ErrInvalidIP},
	}

	for _, tt := range tests {
		n, err := MaskToPrefix(tt.mask)
		if tt.wantErr != nil {
			assert.ErrorIsf(t, err, tt.wantErr, tt.mask)
			continue
		}
		assert.NoErrorf(t, err, tt.mask)
		assert.Equalf(t, tt.want, n, tt.mask)
	}
}

func TestCIDR_MustParse(t *testing.T) {
	// 合法输入
	c := MustParse("192.168.1.0/24")
	assert.Equal(t, "192.168.1.0/24", c.String())

	// 非法输入应 panic
	assert.Panics(t, func() {
		MustParse("bad")
	})
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
