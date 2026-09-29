package cidr

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDR_Mask(t *testing.T) {
	c1 := MustParse("192.168.1.0/24")
	assert.Equal(t, "ffffff00", c1.Mask().String())
	assert.Equal(t, "255.255.255.0", net.IP(c1.Mask()).String())

	c2 := MustParse("2001:db8::/64")
	assert.Equal(t, "ffffffffffffffff0000000000000000", c2.Mask().String())
	assert.Equal(t, "ffff:ffff:ffff:ffff::", net.IP(c2.Mask()).String())
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
