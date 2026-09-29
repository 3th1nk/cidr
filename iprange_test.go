package cidr

import (
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
