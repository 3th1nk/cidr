package cidr

import "testing"

func TestSortCIDR(t *testing.T) {
	var arr = []*CIDR{
		ParseNoError("192.168.1.192/26"),
		ParseNoError("192.168.1.0/26"),
		ParseNoError("192.168.1.64/26"),
		ParseNoError("192.168.1.128/26"),
	}
	t.Log("order by asc:")
	SortCIDRAsc(arr)
	for _, c := range arr {
		t.Log(c.String())
	}

	t.Log("order by desc:")
	SortCIDRDesc(arr)
	for _, c := range arr {
		t.Log(c.String())
	}
}
