package cidr

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSortCIDR(t *testing.T) {
	arr := []*CIDR{
		ParseNoError("192.168.1.192/26"),
		ParseNoError("192.168.1.0/26"),
		ParseNoError("192.168.1.64/26"),
		ParseNoError("192.168.1.128/26"),
	}

	SortCIDRAsc(arr)
	assert.Equal(t, []string{
		"192.168.1.0/26",
		"192.168.1.64/26",
		"192.168.1.128/26",
		"192.168.1.192/26",
	}, cidrStrings(arr))

	SortCIDRDesc(arr)
	assert.Equal(t, []string{
		"192.168.1.192/26",
		"192.168.1.128/26",
		"192.168.1.64/26",
		"192.168.1.0/26",
	}, cidrStrings(arr))
}

// 同 IP 不同掩码,按掩码长度排序
func TestSortCIDR_SameIP(t *testing.T) {
	arr := []*CIDR{
		ParseNoError("10.0.0.0/24"),
		ParseNoError("10.0.0.0/16"),
	}

	SortCIDRAsc(arr)
	assert.Equal(t, []string{"10.0.0.0/16", "10.0.0.0/24"}, cidrStrings(arr))

	SortCIDRDesc(arr)
	assert.Equal(t, []string{"10.0.0.0/24", "10.0.0.0/16"}, cidrStrings(arr))
}
