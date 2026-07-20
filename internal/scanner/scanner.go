package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"time"
)

type LookupResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type Config struct {
	Timeout             time.Duration
	TLSInsecureForTests bool
	TestAllowedHostToIP map[string]net.IP
}

type Scanner struct {
	resolver LookupResolver
	config   Config
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Hostname      string    `json:"hostname"`
	ResolvedIPs   []string  `json:"resolved_ips"`
	TLS           TLSReport `json:"tls"`
	Findings      []Finding `json:"findings"`
	ScannedAt     time.Time `json:"scanned_at"`
}

type TLSReport struct {
	Version       string    `json:"version"`
	CipherSuite   string    `json:"cipher_suite"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DNSNames      []string  `json:"dns_names"`
	DaysRemaining int       `json:"days_remaining"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

func NewResolver(address string) LookupResolver {
	if address == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", address)
	}}
}

func New(resolver LookupResolver, cfg Config) *Scanner {
	return &Scanner{resolver: resolver, config: cfg}
}

func (s *Scanner) Scan(parent context.Context, hostname string) (Report, error) {
	host, err := NormalizeHostname(hostname)
	if err != nil {
		return Report{}, err
	}
	ctx, cancel := context.WithTimeout(parent, s.config.Timeout)
	defer cancel()

	addresses, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return Report{}, fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(addresses) == 0 {
		return Report{}, fmt.Errorf("DNS lookup returned no addresses")
	}

	allowedTestIP, testHost := s.config.TestAllowedHostToIP[host]
	unique := make(map[string]net.IP)
	for _, address := range addresses {
		ip := address.IP
		if err := ValidatePublicIP(ip); err != nil && !(testHost && ip.Equal(allowedTestIP)) {
			return Report{}, err
		}
		unique[ip.String()] = ip
	}
	ips := make([]string, 0, len(unique))
	for value := range unique {
		ips = append(ips, value)
	}
	sort.Strings(ips)

	var conn *tls.Conn
	var lastErr error
	for _, ip := range ips {
		dialer := &net.Dialer{Timeout: s.config.Timeout / 2}
		conn, lastErr = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
			ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: s.config.TLSInsecureForTests && testHost, // #nosec G402 -- locked to an explicit APP_ENV=test allowlist.
		})
		if lastErr == nil {
			break
		}
	}
	if conn == nil {
		return Report{}, fmt.Errorf("TLS connection failed: %w", lastErr)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Report{}, fmt.Errorf("TLS peer returned no certificate")
	}
	cert := state.PeerCertificates[0]
	report := Report{
		SchemaVersion: "1.0.0", Hostname: host, ResolvedIPs: ips, ScannedAt: time.Now().UTC(),
		TLS: certificateReport(state, cert),
	}
	report.Findings = findings(report.TLS, s.config.TLSInsecureForTests && testHost)
	return report, nil
}

func certificateReport(state tls.ConnectionState, cert *x509.Certificate) TLSReport {
	return TLSReport{
		Version: tlsVersion(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		DNSNames: append([]string(nil), cert.DNSNames...), DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
	}
}

func findings(tlsReport TLSReport, fixture bool) []Finding {
	result := []Finding{{Code: "TLS_SUPPORTED", Severity: "info", Title: "TLS endpoint available", Evidence: tlsReport.Version + " / " + tlsReport.CipherSuite}}
	if tlsReport.DaysRemaining < 14 {
		result = append(result, Finding{Code: "CERT_EXPIRES_SOON", Severity: "high", Title: "Certificate expires soon", Evidence: fmt.Sprintf("%d days remaining", tlsReport.DaysRemaining)})
	} else if tlsReport.DaysRemaining < 30 {
		result = append(result, Finding{Code: "CERT_RENEWAL_DUE", Severity: "medium", Title: "Certificate renewal is due", Evidence: fmt.Sprintf("%d days remaining", tlsReport.DaysRemaining)})
	} else {
		result = append(result, Finding{Code: "CERT_VALIDITY", Severity: "info", Title: "Certificate validity is healthy", Evidence: fmt.Sprintf("%d days remaining", tlsReport.DaysRemaining)})
	}
	if fixture {
		result = append(result, Finding{Code: "TEST_FIXTURE", Severity: "info", Title: "Deterministic test fixture", Evidence: "Certificate trust verification disabled only for the explicit test target."})
	}
	return result
}

func tlsVersion(value uint16) string {
	switch value {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%x", value)
	}
}
