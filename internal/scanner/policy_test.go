package scanner

import (
	"net"
	"testing"
)

func TestValidatePublicIP(t *testing.T) {
	t.Parallel()
	denied := []string{
		"10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1",
		"::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:127.0.0.1",
	}
	for _, value := range denied {
		if err := ValidatePublicIP(net.ParseIP(value)); err == nil {
			t.Errorf("expected %s to be denied", value)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, value := range allowed {
		if err := ValidatePublicIP(net.ParseIP(value)); err != nil {
			t.Errorf("expected %s to be allowed: %v", value, err)
		}
	}
}
