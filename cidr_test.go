package cidr

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEach(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")
	c.Each(func(ip string) bool {
		t.Log(ip)
		return true
	})
}

func TestEachFrom(t *testing.T) {
	c := ParseNoError("192.168.1.0/24")
	_ = c.EachFrom("192.168.1.230", func(ip string) bool {
		t.Log(ip)
		return true
	})
}

func TestMask(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	t.Log(c1.Mask())

	c2 := ParseNoError("2001:db8::/64")
	t.Log(c2.Mask())
}

func TestBroadcast(t *testing.T) {
	c1 := ParseNoError("192.168.2.0/24")
	t.Log(c1.Broadcast())

	c2 := ParseNoError("2001:db8::/64")
	t.Log(c2.Broadcast())
}

func TestIPRange(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	start1, end1 := c1.IPRange()
	t.Log(c1.IPCount().String(), start1, end1)

	c2 := ParseNoError("2001:db8::/64")
	start2, end2 := c2.IPRange()
	t.Log(c2.IPCount().String(), start2, end2)

	c3 := ParseNoError("2001:db8::/8")
	start3, end3 := c3.IPRange()
	t.Log(c3.IPCount().String(), start3, end3)
}

func TestSubNetting(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	cs1, _ := c1.SubNetting(MethodSubnetNum, 256)
	t.Log(c1.CIDR(), "按子网数量划分:")
	for _, c := range cs1 {
		t.Log(c.CIDR())
	}

	c2 := ParseNoError("2001:db8::/64")
	cs2, _ := c2.SubNetting(MethodSubnetNum, 4)
	t.Log(c2.CIDR(), "按子网数量划分:")
	for _, c := range cs2 {
		t.Log(c.CIDR())
	}

	c3 := ParseNoError("192.168.1.0/24")
	cs3, _ := c3.SubNetting(MethodHostNum, 64)
	t.Log(c3.CIDR(), "按主机数量划分:")
	for _, c := range cs3 {
		t.Log(c.CIDR())
	}
}

func TestSubNet(t *testing.T) {
	c1 := ParseNoError("192.168.1.0/24")
	cs1, _ := c1.SubNet(25)
	assert.Equal(t, 2, len(cs1))
	assert.Equal(t, "192.168.1.0", cs1[0].IP().String())
	ones, bits := cs1[0].MaskSize()
	assert.Equal(t, 25, ones)
	assert.Equal(t, 32, bits)
	assert.Equal(t, "192.168.1.128", cs1[1].IP().String())

	csErr, err := c1.SubNet(23)
	assert.Equal(t, 0, len(csErr))
	assert.Errorf(t, err, "")

	c2 := ParseNoError("2001:db8::/64")
	cs2, _ := c2.SubNet(68)
	assert.Equal(t, 16, len(cs2))
}

func TestCidrString(t *testing.T) {
	var cd *CIDR
	for _, cs := range []string{"192.168.1.0/24", "192.168.1.1/24", "192.168.1.1/32"} {
		cd = ParseNoError(cs)
		assert.Equal(t, cs, cd.String())
	}
	for _, cs := range []string{"2001:db8::/64", "2001:db8::/128"} {
		cd = ParseNoError(cs)
		assert.Equal(t, cs, cd.String())
	}
}

func TestSuperNetting(t *testing.T) {
	ns4 := []string{
		"192.168.1.0/26",
		"192.168.1.192/26",
		"192.168.1.128/26",
		"192.168.1.64/26",
	}
	c1, err := SuperNetting(ns4)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log(c1.CIDR())

	ns6 := []string{
		"2001:db8::/66",
		"2001:db8:0:0:8000::/66",
		"2001:db8:0:0:4000::/66",
		"2001:db8:0:0:c000::/66",
	}
	c2, err := SuperNetting(ns6)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log(c2.CIDR())
}
