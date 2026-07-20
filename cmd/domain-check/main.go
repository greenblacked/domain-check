package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/greenblacked/domain-check/internal/api"
	"github.com/greenblacked/domain-check/internal/scanner"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://127.0.0.1:" + envOr("PORT", "8080") + "/health")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	if os.Getenv("FIXTURE_SERVER") == "1" {
		if err := runFixture(logger); err != nil {
			logger.Error("fixture stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	resolver := scanner.NewResolver(cfg.DNSResolver)
	svc := scanner.New(resolver, scanner.Config{
		Timeout:             cfg.ScanTimeout,
		TLSInsecureForTests: cfg.TLSInsecureForTests,
		TestAllowedHostToIP: cfg.TestTargets,
	})
	handler := api.New(api.Config{
		InternalGateway: cfg.InternalGateway,
		MaxConcurrent:   cfg.MaxConcurrent,
		Retention:       cfg.Retention,
	}, svc, logger)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.ScanTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logger.Info("server listening", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

type config struct {
	Port                string
	DNSResolver         string
	InternalGateway     string
	ScanTimeout         time.Duration
	Retention           time.Duration
	MaxConcurrent       int
	TLSInsecureForTests bool
	TestTargets         map[string]net.IP
}

func loadConfig() (config, error) {
	cfg := config{
		Port:            envOr("PORT", "8080"),
		DNSResolver:     os.Getenv("DNS_RESOLVER"),
		InternalGateway: envOr("INTERNAL_GATEWAY", "cloudflare-worker-v1"),
		ScanTimeout:     durationOr("SCAN_TIMEOUT", 12*time.Second),
		Retention:       durationOr("SCAN_RETENTION", 15*time.Minute),
		MaxConcurrent:   intOr("MAX_CONCURRENT_SCANS", 8),
		TestTargets:     make(map[string]net.IP),
	}
	if os.Getenv("TLS_INSECURE_FIXTURE") == "1" || os.Getenv("TEST_TARGETS") != "" {
		if os.Getenv("APP_ENV") != "test" {
			return cfg, errors.New("test-only network overrides require APP_ENV=test")
		}
		cfg.TLSInsecureForTests = os.Getenv("TLS_INSECURE_FIXTURE") == "1"
		for _, item := range strings.Split(os.Getenv("TEST_TARGETS"), ",") {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 || net.ParseIP(parts[1]) == nil {
				return cfg, fmt.Errorf("invalid TEST_TARGETS entry %q", item)
			}
			cfg.TestTargets[strings.ToLower(parts[0])] = net.ParseIP(parts[1])
		}
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) time.Duration {
	if value := os.Getenv(name); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func intOr(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

func runFixture(logger *slog.Logger) error {
	cert, err := selfSignedCertificate()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"fixture": "ok"})
	})
	server := &http.Server{Addr: ":443", Handler: mux, ReadHeaderTimeout: 3 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	logger.Info("TLS fixture listening", "port", 443)
	listener, err := tls.Listen("tcp", server.Addr, server.TLSConfig)
	if err != nil {
		return err
	}
	return server.Serve(listener)
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.test"},
		DNSNames: []string{"fixture.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
