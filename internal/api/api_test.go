package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// blockingScanner holds every scan open until released, so a test can observe
// how many run concurrently.
type blockingScanner struct {
	started chan struct{}
	release chan struct{}
}

func (b blockingScanner) Scan(_ context.Context, hostname string) (scanner.Report, error) {
	b.started <- struct{}{}
	<-b.release
	return scanner.Report{SchemaVersion: "1.0.0", Hostname: hostname, ScannedAt: time.Now().UTC()}, nil
}

func post(handler *Handler, scanID string) *httptest.ResponseRecorder {
	body := `{"hostname":"fixture.test","scan_id":"` + scanID + `","correlation_id":"c"}`
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/scans", strings.NewReader(body))
	request.Header.Set("X-Internal-Gateway", "test-gateway")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func scanID(n int) string {
	return fmt.Sprintf("123e4567-e89b-42d3-a456-%012d", n)
}

// TestConcurrencyLimitHoldsUnderRace is the regression test for the capacity
// check and the counter increment being separate steps: simultaneous requests
// could all observe spare capacity and overshoot MaxConcurrent.
func TestConcurrencyLimitHoldsUnderRace(t *testing.T) {
	const limit = 4
	const callers = 40
	svc := blockingScanner{started: make(chan struct{}, callers), release: make(chan struct{})}
	handler := New(Config{InternalGateway: "test-gateway", MaxConcurrent: limit, Retention: time.Minute}, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))

	var wg sync.WaitGroup
	var accepted, refused atomic.Int64
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all requests at once to maximise contention
			switch code := post(handler, scanID(i)).Code; code {
			case http.StatusAccepted:
				accepted.Add(1)
			case http.StatusTooManyRequests:
				refused.Add(1)
			default:
				t.Errorf("unexpected status %d", code)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := accepted.Load(); got != limit {
		t.Fatalf("accepted %d scans, want exactly %d", got, limit)
	}
	if got := refused.Load(); got != callers-limit {
		t.Fatalf("refused %d scans, want %d", got, callers-limit)
	}
	if got := handler.active.Load(); got != limit {
		t.Fatalf("active counter = %d, want %d", got, limit)
	}
	close(svc.release)
}

// TestDuplicateScanReleasesItsSlot guards the slot accounting on the path where
// a scan is admitted and then rejected for a duplicate identifier.
func TestDuplicateScanReleasesItsSlot(t *testing.T) {
	handler := New(Config{InternalGateway: "test-gateway", MaxConcurrent: 1, Retention: time.Minute}, fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if code := post(handler, scanID(1)).Code; code != http.StatusAccepted {
		t.Fatalf("first create = %d, want 202", code)
	}
	deadline := time.Now().Add(time.Second)
	for handler.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if code := post(handler, scanID(1)).Code; code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", code)
	}
	if got := handler.active.Load(); got != 0 {
		t.Fatalf("duplicate scan leaked a slot: active = %d, want 0", got)
	}
	// The leaked slot would otherwise make this fail at MaxConcurrent 1.
	if code := post(handler, scanID(2)).Code; code != http.StatusAccepted {
		t.Fatalf("create after duplicate = %d, want 202", code)
	}
}
