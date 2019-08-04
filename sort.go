package cidr

import (
	"bytes"
	"sort"
)

// 升序
func AscSortCIDRs(cs []*CIDR) {
	sort.Slice(cs, func(i, j int) bool {
		if n := bytes.Compare(cs[i].ipnet.IP, cs[j].ipnet.IP); n != 0 {
			return n < 0
		}

		if n := bytes.Compare(cs[i].ipnet.Mask, cs[j].ipnet.Mask); n != 0 {
			return n < 0
		}

		return false
	})
}

// 降序
func DescSortCIDRs(cs []*CIDR) {
	sort.Slice(cs, func(i, j int) bool {
		if n := bytes.Compare(cs[i].ipnet.IP, cs[j].ipnet.IP); n != 0 {
			return n >= 0
		}

		if n := bytes.Compare(cs[i].ipnet.Mask, cs[j].ipnet.Mask); n != 0 {
			return n >= 0
		}

		return false
	})
}
