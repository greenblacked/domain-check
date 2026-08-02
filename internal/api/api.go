package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greenblacked/domain-check/internal/scanner"
)

const maxBodyBytes = 1024

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Config struct {
	InternalGateway string
	MaxConcurrent   int
	Retention       time.Duration
}

type ScanService interface {
	Scan(context.Context, string) (scanner.Report, error)
}

type Handler struct {
	config  Config
	scanner ScanService
	logger  *slog.Logger
	scans   sync.Map
	active  atomic.Int64
	ready   atomic.Bool
}

type createRequest struct {
	Hostname      string `json:"hostname"`
	ScanID        string `json:"scan_id"`
	CorrelationID string `json:"correlation_id"`
}

type Scan struct {
	ID            string          `json:"id"`
	Hostname      string          `json:"hostname"`
	CorrelationID string          `json:"correlation_id"`
	Status        string          `json:"status"`
	Progress      int             `json:"progress"`
	CreatedAt     time.Time       `json:"created_at"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty"`
	Report        *scanner.Report `json:"report,omitempty"`
	Error         string          `json:"error,omitempty"`
	mu            sync.RWMutex
}

func New(cfg Config, service ScanService, logger *slog.Logger) *Handler {
	h := &Handler{config: cfg, scanner: service, logger: logger}
	h.ready.Store(true)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/ready":
		if !h.ready.Load() {
			writeError(w, http.StatusServiceUnavailable, "not_ready", "scanner is not ready")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	case r.Method == http.MethodPost && r.URL.Path == "/internal/v1/scans":
		h.create(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/internal/v1/scans/"):
		h.get(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Internal-Gateway") != h.config.InternalGateway {
		writeError(w, http.StatusForbidden, "forbidden", "internal gateway header required")
		return false
	}
	return true
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var input createRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request must match the typed scan contract")
		return
	}
	if err := ensureEOF(decoder); err != nil || !idPattern.MatchString(input.ScanID) || input.CorrelationID == "" || len(input.CorrelationID) > 128 {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid scan or correlation identifier")
		return
	}
	host, err := scanner.NormalizeHostname(input.Hostname)
	if err != nil || host != input.Hostname {
		writeError(w, http.StatusBadRequest, "invalid_hostname", "hostname must already be normalized")
		return
	}
	if !h.acquire() {
		writeError(w, http.StatusTooManyRequests, "concurrency_limit", "scanner is at capacity")
		return
	}
	now := time.Now().UTC()
	item := &Scan{ID: input.ScanID, Hostname: host, CorrelationID: input.CorrelationID, Status: "queued", Progress: 5, CreatedAt: now}
	if _, loaded := h.scans.LoadOrStore(item.ID, item); loaded {
		h.release()
		writeError(w, http.StatusConflict, "duplicate_scan", "scan identifier already exists")
		return
	}
	go h.execute(item)
	writeJSON(w, http.StatusAccepted, item.snapshot())
}

// acquire claims one of the MaxConcurrent scan slots. Reading the counter and
// then incrementing it as separate steps let simultaneous requests all observe
// spare capacity and overshoot the limit, so the claim is a single atomic step
// that retries only when another request won the race.
func (h *Handler) acquire() bool {
	limit := int64(h.config.MaxConcurrent)
	for {
		current := h.active.Load()
		if current >= limit {
			return false
		}
		if h.active.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (h *Handler) release() {
	h.active.Add(-1)
}

func (h *Handler) execute(item *Scan) {
	defer h.release()
	item.update("running", 25, nil, "")
	report, err := h.scanner.Scan(context.Background(), item.Hostname)
	if err != nil {
		item.update("failed", 100, nil, publicScanError(err))
		h.logger.Warn("scan failed", "scan_id", item.ID, "correlation_id", item.CorrelationID, "hostname", item.Hostname, "error", err)
	} else {
		item.update("complete", 100, &report, "")
		h.logger.Info("scan complete", "scan_id", item.ID, "correlation_id", item.CorrelationID, "hostname", item.Hostname)
	}
	time.AfterFunc(h.config.Retention, func() { h.scans.Delete(item.ID) })
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/internal/v1/scans/")
	if !idPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan identifier")
		return
	}
	value, ok := h.scans.Load(id)
	if !ok {
		writeError(w, http.StatusNotFound, "scan_not_found", "scan not found or expired")
		return
	}
	writeJSON(w, http.StatusOK, value.(*Scan).snapshot())
}

func (s *Scan) update(status string, progress int, report *scanner.Report, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status, s.Progress, s.Report, s.Error = status, progress, report, message
	now := time.Now().UTC()
	if status == "complete" || status == "failed" {
		s.CompletedAt = &now
	}
}

func (s *Scan) snapshot() Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Scan{ID: s.ID, Hostname: s.Hostname, CorrelationID: s.CorrelationID, Status: s.Status, Progress: s.Progress, CreatedAt: s.CreatedAt, CompletedAt: s.CompletedAt, Report: s.Report, Error: s.Error}
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func publicScanError(err error) string {
	message := err.Error()
	if strings.Contains(message, "private, reserved") {
		return message
	}
	if strings.Contains(message, "context deadline") || strings.Contains(message, "i/o timeout") {
		return "scan timed out"
	}
	return "scan could not be completed"
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
