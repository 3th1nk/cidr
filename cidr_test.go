package cidr

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
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

	// 非法输入返回 ErrInvalidCIDR
	_, err = Parse("bad")
	assert.ErrorIs(t, err, ErrInvalidCIDR)
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

func TestCIDR_MustParse(t *testing.T) {
	// 合法输入
	c := MustParse("192.168.1.0/24")
	assert.Equal(t, "192.168.1.0/24", c.String())

	// 非法输入应 panic
	assert.Panics(t, func() {
		MustParse("bad")
	})
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

// cidrStrings returns the string representations of the CIDRs
func cidrStrings(cs []*CIDR) []string {
	ss := make([]string, 0, len(cs))
	for _, c := range cs {
		ss = append(ss, c.String())
	}
	return ss
}
