package cidr

import "sort"

// SortCIDRAsc sort cidr slice order by ip,mask asc
func SortCIDRAsc(cs []*CIDR) {
	sortCIDR(cs, "asc")
}

// SortCIDRDesc sort cidr slice order by ip,mask desc
func SortCIDRDesc(cs []*CIDR) {
	sortCIDR(cs, "desc")
}

func sortCIDR(cs []*CIDR, order string) {
	sort.Slice(cs, func(i, j int) bool {
		if n := IPCompare(cs[i].ipNet.IP, cs[j].ipNet.IP); n != 0 {
			if order == "desc" {
				return n >= 0
			}
			return n < 0
		}

		i1, _ := cs[i].ipNet.Mask.Size()
		j1, _ := cs[j].ipNet.Mask.Size()
		if order == "desc" {
			return i1 > j1
		}
		return i1 < j1
	})
}
