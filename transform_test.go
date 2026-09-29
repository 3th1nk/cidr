package cidr

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCIDR_Supernet(t *testing.T) {
	// 向上卷
	c, err := MustParse("192.168.1.0/24").Supernet(16)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.0.0/16", c.String())

	// host bits 会被掩掉
	c, err = MustParse("192.168.1.130/25").Supernet(24)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())

	// 等值:原样返回
	c, err = MustParse("192.168.1.0/24").Supernet(24)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.0/24", c.String())

	// IPv6
	c, err = MustParse("2001:db8:1::/48").Supernet(32)
	assert.NoError(t, err)
	assert.Equal(t, "2001:db8::/32", c.String())

	// 非法:newOnes 大于当前前缀或为负
	_, err = MustParse("192.168.1.0/24").Supernet(25)
	assert.ErrorIs(t, err, ErrNumOutOfRange)

	_, err = MustParse("192.168.1.0/24").Supernet(-1)
	assert.ErrorIs(t, err, ErrNumOutOfRange)
}

func TestCollapseCIDRs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "contained is dropped",
			in:   []string{"192.168.1.0/24", "192.168.1.0/25"},
			want: []string{"192.168.1.0/24"},
		},
		{
			name: "adjacent are merged",
			in:   []string{"192.168.1.0/25", "192.168.1.128/25"},
			want: []string{"192.168.1.0/24"},
		},
		{
			name: "separated are kept and sorted",
			in:   []string{"192.168.2.0/24", "192.168.1.0/24"},
			want: []string{"192.168.1.0/24", "192.168.2.0/24"},
		},
		{
			name: "mixed",
			in:   []string{"10.1.0.0/16", "192.168.1.128/25", "10.0.0.0/8", "192.168.1.0/24"},
			want: []string{"10.0.0.0/8", "192.168.1.0/24"},
		},
		{
			name: "upper boundary adjacent",
			in:   []string{"255.255.255.0/25", "255.255.255.128/25"},
			want: []string{"255.255.255.0/24"},
		},
		{
			name: "mixed families, v4 first",
			in:   []string{"2001:db9::/32", "192.168.1.0/24", "2001:db8::/32"},
			want: []string{"192.168.1.0/24", "2001:db8::/31"},
		},
		{
			name: "empty",
			in:   nil,
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := make([]*CIDR, 0, len(tt.in))
			for _, s := range tt.in {
				cs = append(cs, MustParse(s))
			}
			assert.Equal(t, tt.want, cidrStrings(CollapseCIDRs(cs)))
		})
	}
}

func TestRangeToCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		start   string
		end     string
		want    []string
		wantErr error
	}{
		{"aligned", "192.168.1.0", "192.168.1.255", []string{"192.168.1.0/24"}, nil},
		{"single ip", "192.168.1.1", "192.168.1.1", []string{"192.168.1.1/32"}, nil},
		{
			"unaligned",
			"192.168.1.1", "192.168.1.10",
			[]string{"192.168.1.1/32", "192.168.1.2/31", "192.168.1.4/30", "192.168.1.8/31", "192.168.1.10/32"},
			nil,
		},
		{"full range", "0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}, nil},
		{"v6", "2001:db8::", "2001:db8::ffff:ffff", []string{"2001:db8::/96"}, nil},
		{"mapped equals v4", "::ffff:192.168.1.0", "192.168.1.255", []string{"192.168.1.0/24"}, nil},
		// 非法输入
		{"start after end", "192.168.1.10", "192.168.1.1", nil, ErrInvalidRange},
		{"cross family", "192.168.1.1", "2001:db8::1", nil, ErrNotSameFamily},
		{"invalid start", "bad", "192.168.1.1", nil, ErrInvalidIP},
		{"invalid end", "192.168.1.1", "bad", nil, ErrInvalidIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := RangeToCIDRs(tt.start, tt.end)
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

func TestSpanningCIDR(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    string
		wantErr error
	}{
		{
			name: "adjacent halves",
			in:   []string{"192.168.1.0/25", "192.168.1.128/25"},
			want: "192.168.1.0/24",
		},
		{
			name: "non-aligned minimum supernet",
			in:   []string{"192.168.1.0/25", "192.168.1.128/25", "192.168.2.0/24"},
			want: "192.168.0.0/22",
		},
		{
			name: "single cidr",
			in:   []string{"192.168.1.0/24"},
			want: "192.168.1.0/24",
		},
		{
			name: "different masks",
			in:   []string{"10.0.0.0/8", "10.128.0.0/9"},
			want: "10.0.0.0/8",
		},
		{
			name: "v6",
			in:   []string{"2001:db8::/66", "2001:db8:0:0:4000::/66", "2001:db8:0:0:8000::/66", "2001:db8:0:0:c000::/66"},
			want: "2001:db8::/64",
		},
		{
			name: "mapped equals v4",
			in:   []string{"::ffff:192.168.1.0/120", "192.168.1.128/25"},
			want: "192.168.1.0/24",
		},
		// 非法输入
		{name: "empty", in: nil, wantErr: ErrInvalidCIDR},
		{name: "cross family", in: []string{"192.168.1.0/24", "2001:db8::/32"}, wantErr: ErrNotSameFamily},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := make([]*CIDR, 0, len(tt.in))
			for _, s := range tt.in {
				cs = append(cs, MustParse(s))
			}
			c, err := SpanningCIDR(cs)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, c)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, c.String())
		})
	}

	// 列表中的 nil 元素
	t.Run("nil element", func(t *testing.T) {
		cs := []*CIDR{MustParse("192.168.1.0/24"), nil}
		c, err := SpanningCIDR(cs)
		assert.ErrorIs(t, err, ErrInvalidCIDR)
		assert.Nil(t, c)
	})
}

func TestCIDR_Exclude(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		sub     string
		want    []string
		wantErr error
	}{
		{"lower half", "192.168.1.0/24", "192.168.1.0/25", []string{"192.168.1.128/25"}, nil},
		{"upper half", "192.168.1.0/24", "192.168.1.128/25", []string{"192.168.1.0/25"}, nil},
		{
			"middle block",
			"192.168.1.0/24", "192.168.1.64/26",
			[]string{"192.168.1.0/26", "192.168.1.128/25"},
			nil,
		},
		{
			"nested exclusion",
			"10.0.0.0/8", "10.1.2.0/24",
			[]string{
				"10.0.0.0/16", "10.1.0.0/23", "10.1.3.0/24", "10.1.4.0/22", "10.1.8.0/21",
				"10.1.16.0/20", "10.1.32.0/19", "10.1.64.0/18", "10.1.128.0/17", "10.2.0.0/15",
				"10.4.0.0/14", "10.8.0.0/13", "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10",
				"10.128.0.0/9",
			},
			nil,
		},
		{"equal returns empty", "192.168.1.0/24", "192.168.1.0/24", []string{}, nil},
		// 非法输入
		{"sub outside", "192.168.1.0/24", "192.168.2.0/24", nil, ErrIPNotInCIDR},
		{"sub larger", "192.168.1.0/25", "192.168.1.0/24", nil, ErrIPNotInCIDR},
		{"cross family", "192.168.1.0/24", "2001:db8::/32", nil, ErrNotSameFamily},
		{"nil sub", "192.168.1.0/24", "", nil, ErrInvalidCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sub *CIDR
			if tt.sub != "" {
				sub = MustParse(tt.sub)
			}
			cs, err := MustParse(tt.cidr).Exclude(sub)
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
