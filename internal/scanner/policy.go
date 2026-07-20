package scanner

import (
	"fmt"
	"net"
	"net/netip"
)

var deniedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:2::/48", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func ValidatePublicIP(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return errorsIP(ip)
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return errorsIP(ip)
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(addr) {
			return errorsIP(ip)
		}
	}
	return nil
}

func errorsIP(ip net.IP) error {
	return fmt.Errorf("resolved address %s is private, reserved, or non-routable", ip.String())
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}
