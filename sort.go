package cidr

import "sort"

const (
	sortOrderAsc = iota
	sortOrderDesc
)

// SortCIDRAsc sort cidr slice order by ip,mask asc
func SortCIDRAsc(cs []*CIDR) {
	sortCIDR(cs, sortOrderAsc)
}

// SortCIDRDesc sort cidr slice order by ip,mask desc
func SortCIDRDesc(cs []*CIDR) {
	sortCIDR(cs, sortOrderDesc)
}

func sortCIDR(cs []*CIDR, order int) {
	isDesc := order == sortOrderDesc
	sort.Slice(cs, func(i, j int) bool {
		if n := IPCompare(cs[i].ipNet.IP, cs[j].ipNet.IP); n != 0 {
			if isDesc {
				return n >= 0
			}
			return n < 0
		}

		i1, _ := cs[i].ipNet.Mask.Size()
		j1, _ := cs[j].ipNet.Mask.Size()
		if isDesc {
			return i1 > j1
		}
		return i1 < j1
	})
}
