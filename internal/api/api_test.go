package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenblacked/domain-check/internal/scanner"
)

type fakeScanner struct{}

func (fakeScanner) Scan(_ context.Context, hostname string) (scanner.Report, error) {
	return scanner.Report{SchemaVersion: "1.0.0", Hostname: hostname, ResolvedIPs: []string{"1.1.1.1"}, ScannedAt: time.Now().UTC()}, nil
}

func TestCreateAndPoll(t *testing.T) {
	handler := New(Config{InternalGateway: "test-gateway", MaxConcurrent: 2, Retention: time.Minute}, fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := `{"hostname":"fixture.test","scan_id":"123e4567-e89b-42d3-a456-426614174000","correlation_id":"test-correlation"}`
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/scans", strings.NewReader(body))
	request.Header.Set("X-Internal-Gateway", "test-gateway")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("create status = %d: %s", response.Code, response.Body.String())
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		poll := httptest.NewRequest(http.MethodGet, "/internal/v1/scans/123e4567-e89b-42d3-a456-426614174000", nil)
		poll.Header.Set("X-Internal-Gateway", "test-gateway")
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, poll)
		var scan Scan
		if err := json.Unmarshal(result.Body.Bytes(), &scan); err != nil {
			t.Fatal(err)
		}
		if scan.Status == "complete" {
			if scan.Report == nil || scan.Report.SchemaVersion != "1.0.0" {
				t.Fatalf("unexpected report: %#v", scan.Report)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scan did not complete")
}

func TestRejectsUnknownFieldsAndMissingGateway(t *testing.T) {
	handler := New(Config{InternalGateway: "test-gateway", MaxConcurrent: 1, Retention: time.Minute}, fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/scans", strings.NewReader(`{"hostname":"example.com","upstream":"http://127.0.0.1"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/internal/v1/scans", strings.NewReader(`{"hostname":"example.com","scan_id":"123e4567-e89b-42d3-a456-426614174000","correlation_id":"x","port":22}`))
	request.Header.Set("X-Internal-Gateway", "test-gateway")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}
