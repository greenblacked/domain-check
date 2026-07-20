package scanner

import (
	"errors"
	"net"
	"strings"
)

var errInvalidHostname = errors.New("hostname must be a valid ASCII DNS name, not an IP address")

// NormalizeHostname deliberately accepts only DNS hostnames. URLs, ports, userinfo,
// resolver choices, and IP literals are outside the public and internal contracts.
func NormalizeHostname(input string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(input))
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil || strings.ContainsAny(host, ":/@[]\\") {
		return "", errInvalidHostname
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", errInvalidHostname
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errInvalidHostname
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", errInvalidHostname
			}
		}
	}
	return host, nil
}
