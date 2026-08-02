package scanner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type stubResolver struct {
	addresses []net.IPAddr
	err       error
}

func (s stubResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return s.addresses, s.err
}

func addrs(values ...string) []net.IPAddr {
	result := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		result = append(result, net.IPAddr{IP: net.ParseIP(value)})
	}
	return result
}

// TestScanRejectsNonPublicAnswer covers the DNS rebinding defense: a resolver
// answer pointing at a reserved range must abort the scan before any dial.
func TestScanRejectsNonPublicAnswer(t *testing.T) {
	t.Parallel()
	for _, answer := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:192.168.0.1"} {
		t.Run(answer, func(t *testing.T) {
			t.Parallel()
			dialed := false
			s := New(stubResolver{addresses: addrs(answer)}, Config{Timeout: time.Second})
			s.dialContext = func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, nil
			}
			if _, err := s.Scan(context.Background(), "rebind.example"); err == nil {
				t.Fatal("expected a reserved address to be rejected")
			} else if !strings.Contains(err.Error(), "private, reserved") {
				t.Fatalf("unexpected error: %v", err)
			}
			if dialed {
				t.Fatal("scanner dialed a reserved address")
			}
		})
	}
}

func TestScanRejectsEmptyResolution(t *testing.T) {
	t.Parallel()
	s := New(stubResolver{addresses: nil}, Config{Timeout: time.Second})
	if _, err := s.Scan(context.Background(), "empty.example"); err == nil {
		t.Fatal("expected an error when DNS returns no addresses")
	}
}

// TestScanBudgetSpansAllAttempts is the regression test for dial timeouts that
// were previously per-address and unbounded by the scan context: N unreachable
// addresses must not cost N times the per-attempt timeout.
func TestScanBudgetSpansAllAttempts(t *testing.T) {
	t.Parallel()
	const budget = 400 * time.Millisecond
	s := New(stubResolver{addresses: addrs("1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1")}, Config{Timeout: budget})
	s.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done() // a black-holed address: never connects, never refuses.
		return nil, ctx.Err()
	}

	start := time.Now()
	if _, err := s.Scan(context.Background(), "slow.example"); err == nil {
		t.Fatal("expected the scan to fail")
	}
	elapsed := time.Since(start)

	// Before the fix this took 4 x (budget/2) = 2x budget, ignoring the scan
	// deadline entirely. It must now stop at the deadline itself.
	if elapsed > budget+150*time.Millisecond {
		t.Fatalf("scan took %v, which exceeds the %v budget", elapsed, budget)
	}
}

func TestScanRespectsCallerCancellation(t *testing.T) {
	t.Parallel()
	s := New(stubResolver{addresses: addrs("1.1.1.1")}, Config{Timeout: 30 * time.Second})
	s.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := s.Scan(ctx, "cancelled.example"); err == nil {
		t.Fatal("expected the scan to fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("scan ignored caller cancellation and took %v", elapsed)
	}
}

func TestScanReportsCertificateAndFindings(t *testing.T) {
	t.Parallel()
	listener := startTLSFixture(t, time.Now().Add(400*24*time.Hour))
	s := newFixtureScanner(stubResolver{addresses: addrs("1.1.1.1")}, listener.Addr().String())

	report, err := s.Scan(context.Background(), "fixture.test")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if report.Hostname != "fixture.test" || report.SchemaVersion != "1.0.0" {
		t.Fatalf("unexpected report identity: %#v", report)
	}
	if len(report.ResolvedIPs) != 1 || report.ResolvedIPs[0] != "1.1.1.1" {
		t.Fatalf("unexpected resolved addresses: %v", report.ResolvedIPs)
	}
	if report.TLS.Version != "TLS 1.3" {
		t.Fatalf("unexpected negotiated version: %q", report.TLS.Version)
	}
	if !strings.Contains(report.TLS.Subject, "fixture.test") {
		t.Fatalf("unexpected certificate subject: %q", report.TLS.Subject)
	}
	if !hasFinding(report.Findings, "CERT_VALIDITY") || !hasFinding(report.Findings, "TLS_SUPPORTED") {
		t.Fatalf("unexpected findings: %#v", report.Findings)
	}
}

func TestScanFlagsExpiringCertificate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		expires time.Duration
		code    string
	}{
		{"about to expire", 5 * 24 * time.Hour, "CERT_EXPIRES_SOON"},
		{"renewal due", 20 * 24 * time.Hour, "CERT_RENEWAL_DUE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listener := startTLSFixture(t, time.Now().Add(test.expires))
			s := newFixtureScanner(stubResolver{addresses: addrs("1.1.1.1")}, listener.Addr().String())
			report, err := s.Scan(context.Background(), "fixture.test")
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if !hasFinding(report.Findings, test.code) {
				t.Fatalf("expected finding %s, got %#v", test.code, report.Findings)
			}
		})
	}
}

// TestScanFallsBackToNextAddress proves the dial loop keeps trying candidates
// after an unreachable one rather than failing the whole scan.
func TestScanFallsBackToNextAddress(t *testing.T) {
	t.Parallel()
	listener := startTLSFixture(t, time.Now().Add(400*24*time.Hour))
	s := newFixtureScanner(stubResolver{addresses: addrs("1.1.1.1", "8.8.8.8")}, listener.Addr().String())
	base := s.dialContext
	s.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "1.1.1.1:") {
			return nil, &net.OpError{Op: "dial", Err: errRefused{}}
		}
		return base(ctx, network, address)
	}
	if _, err := s.Scan(context.Background(), "fixture.test"); err != nil {
		t.Fatalf("scan should have fallen back to the reachable address: %v", err)
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

// newFixtureScanner redirects the fixed port 443 dial onto a local listener
// while leaving hostname, TLS version, and verification policy untouched.
func newFixtureScanner(resolver LookupResolver, target string) *Scanner {
	s := New(resolver, Config{
		Timeout:             5 * time.Second,
		TLSInsecureForTests: true,
		TestAllowedHostToIP: map[string]net.IP{"fixture.test": net.ParseIP("1.1.1.1")},
	})
	base := s.dialContext
	s.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !strings.HasSuffix(address, ":443") {
			return nil, &net.OpError{Op: "dial", Err: errRefused{}}
		}
		return base(ctx, network, target)
	}
	return s
}

func startTLSFixture(t *testing.T, notAfter time.Time) net.Listener {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture.test"},
		DNSNames:     []string{"fixture.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()
	return listener
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
