package cidr

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestCompare(t *testing.T) {
	assert.Equal(t, Compare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.20")), -1)
	assert.Equal(t, Compare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.10")), -1)
	assert.Equal(t, Compare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.2")), 0)
	assert.Equal(t, Compare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.3")), -1)
	assert.Equal(t, Compare(net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1")), 1)
}