package cidr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestCIDR_SuperNetting_Misaligned(t *testing.T) {
	// 连续但未按父网对齐的段,合并结果应按父掩码对齐
	c, err := SuperNetting([]string{"192.168.0.128/25", "192.168.1.0/25"})
	assert.NoError(t, err)
	assert.Equal(t, "192.168.0.0/24", c.String())
	assert.Equal(t, "192.168.0.0", c.Network().String())
	assert.Equal(t, "192.168.0.255", c.EndIP().String())
}
