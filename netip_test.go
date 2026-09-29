package cidr

import (
	"encoding/json"
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

func TestCIDR_MarshalText(t *testing.T) {
	c := MustParse("2001:db8::/32")
	b, err := c.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::/32", string(b))

	// UnmarshalText
	var c2 CIDR
	assert.NoError(t, c2.UnmarshalText([]byte("192.168.1.0/24")))
	assert.Equal(t, "192.168.1.0/24", c2.String())
	assert.ErrorIs(t, c2.UnmarshalText([]byte("bad")), ErrInvalidCIDR)

	// 实现了 TextMarshaler/TextUnmarshaler 后 JSON 自动支持
	type wrapper struct {
		CIDR *CIDR `json:"cidr"`
	}
	data, err := json.Marshal(wrapper{CIDR: MustParse("192.168.1.0/24")})
	assert.NoError(t, err)
	assert.JSONEq(t, `{"cidr":"192.168.1.0/24"}`, string(data))

	var w wrapper
	assert.NoError(t, json.Unmarshal([]byte(`{"cidr":"2001:db8::/32"}`), &w))
	assert.Equal(t, "2001:db8::/32", w.CIDR.String())

	// 非法 JSON 值
	assert.Error(t, json.Unmarshal([]byte(`{"cidr":"bad"}`), &w))
}
