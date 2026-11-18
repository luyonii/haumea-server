package api

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// debugAuth gates a handler on X-Debug-Token (constant-time compare).
// Registered only when cfg.EnableDebug=true and cfg.DebugToken!="" (see Register).
func debugAuth(token string, h http.HandlerFunc) http.HandlerFunc {
	tb := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("X-Debug-Token"))
		if len(got) != len(tb) || subtle.ConstantTimeCompare(got, tb) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// Structured access log, alongside the existing `log` calls elsewhere.
var accessLog = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

// --- counters ---
// shortcut: in-memory counters (map+mutex). Upgrade to Prometheus client or
// atomic-only lock-free structure once more than one server instance runs.
var (
	countersMu sync.Mutex
	counters   = map[string]*uint64{}
)

func metricInc(name, endpoint string) {
	key := name + "{endpoint=\"" + endpoint + "\"}"
	countersMu.Lock()
	p, ok := counters[key]
	if !ok {
		p = new(uint64)
		counters[key] = p
	}
	countersMu.Unlock()
	atomic.AddUint64(p, 1)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Auth is enforced by debugAuth wrapper + Register gate (enable_debug +
	// debug_token). This handler assumes caller already passed that check.
	countersMu.Lock()
	out := make(map[string]uint64, len(counters))
	for k, v := range counters {
		out[k] = atomic.LoadUint64(v)
	}
	countersMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// --- middleware ---

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func observe(path string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		h(sw, r)
		accessLog.Info("req",
			"method", r.Method,
			"path", path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", clientIP(r),
		)
	})
}
