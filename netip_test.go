package cidr

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDR_AsNetip(t *testing.T) {
	// IPv4
	p, err := MustParse("192.168.1.0/24").AsNetip()
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", p.String())
	assert.True(t, p.Addr().Is4())

	// IPv6
	p, err = MustParse("2001:db8::/32").AsNetip()
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::/32", p.String())
	assert.True(t, p.Addr().Is6())

	// v4-mapped 归一为 v4 形式,/120 折算为 /24
	p, err = MustParse("::ffff:192.168.1.0/120").AsNetip()
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", p.String())
	assert.True(t, p.Addr().Is4())

	// 往返:ParseNetip(AsNetip(c)) 等价于 c
	for _, s := range []string{"192.168.1.0/24", "2001:db8::/32", "10.0.0.0/8"} {
		p, err := MustParse(s).AsNetip()
		assert.NoError(t, err)
		c, err := ParseNetip(p)
		assert.NoError(t, err)
		assert.Equal(t, s, c.String(), s)
	}
}

func TestParseNetip(t *testing.T) {
	// IPv4
	c, err := ParseNetip(netip.MustParsePrefix("192.168.1.0/24"))
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())

	// IPv6
	c, err = ParseNetip(netip.MustParsePrefix("2001:db8::/32"))
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::/32", c.String())

	// host bits 会被掩掉(PrefixFrom 构造的 Prefix 的 Addr 可能带 host bits)
	c, err = ParseNetip(netip.PrefixFrom(netip.MustParseAddr("192.168.1.10"), 24))
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())
	assert.Equal(t, "192.168.1.0", c.Network().String())

	// 零值 Prefix 非法
	c, err = ParseNetip(netip.Prefix{})
	assert.ErrorIs(t, err, ErrInvalidCIDR)
	assert.Nil(t, c)
}
