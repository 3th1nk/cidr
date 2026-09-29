package cidr

import "errors"

// Errors returned by this package, can be checked with errors.Is
var (
	// ErrInvalidIP the given string is not a valid IP address
	ErrInvalidIP = errors.New("invalid ip")
	// ErrIPNotInCIDR the given IP is not within the CIDR
	ErrIPNotInCIDR = errors.New("ip is not in the cidr")
	// ErrInvalidCIDR the given string is not a valid CIDR
	ErrInvalidCIDR = errors.New("invalid cidr")
	// ErrInvalidNum the number (or the length of the segments) must be a power of 2
	ErrInvalidNum = errors.New("num must be a power of 2")
	// ErrNumOutOfRange the number is out of the allowed mask range
	ErrNumOutOfRange = errors.New("num out of range")
	// ErrExceedMaxLimit the number of subnets exceeds the maximum limit
	ErrExceedMaxLimit = errors.New("subnet number exceeds maximum limit")
	// ErrUnsupportedMethod the SubNetting method is not supported
	ErrUnsupportedMethod = errors.New("unsupported method")
	// ErrNotSameMask the CIDRs do not have the same mask
	ErrNotSameMask = errors.New("not the same mask")
	// ErrNotContiguous the segments are not contiguous
	ErrNotContiguous = errors.New("not contiguous segments")
	// ErrInvalidRange the given IP range is invalid (bad order or cross-family)
	ErrInvalidRange = errors.New("invalid ip range")
	// ErrNotSameFamily the CIDRs do not belong to the same address family
	ErrNotSameFamily = errors.New("not the same address family")
	// ErrInvalidMask the given string is not a valid contiguous netmask
	ErrInvalidMask = errors.New("invalid netmask")
)
