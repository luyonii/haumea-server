package api

import (
	"crypto/subtle"
	"net/http"
	"strconv"
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

// statusWriter captures the response code for logging/metrics.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// observe wraps h with:
//   - request_id (generated or honored from X-Request-ID)
//   - per-route rate limiting (returns 429 before the handler runs)
//   - zap access log (never logs session tokens, keys, HMACs, or full license keys)
//   - prometheus request + duration counters
func observe(path string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-ID", rid)
		ctx := WithRequestID(r.Context(), rid)
		r = r.WithContext(ctx)

		ip := clientIP(r)

		// Per-route rate limit (in-process token bucket).
		if rl := packageRouteLimiter.load(); rl != nil {
			if key, ok := routeKeyForPath[path]; ok && !rl.Allow(key, ip) {
				metricInc("rate_limited_total", path)
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
				httpRequestsTotal.WithLabelValues(path, "429").Inc()
				httpRequestDuration.WithLabelValues(path).Observe(time.Since(start).Seconds())
				L().Infow("req",
					"request_id", rid,
					"route", path,
					"status", 429,
					"duration_ms", time.Since(start).Milliseconds(),
					"remote_ip", ip,
					"limited", true,
				)
				return
			}
		}

		sw := &statusWriter{ResponseWriter: w, status: 200}
		h(sw, r)

		dur := time.Since(start)
		httpRequestsTotal.WithLabelValues(path, strconv.Itoa(sw.status)).Inc()
		httpRequestDuration.WithLabelValues(path).Observe(dur.Seconds())
		L().Infow("req",
			"request_id", rid,
			"route", path,
			"status", sw.status,
			"duration_ms", dur.Milliseconds(),
			"remote_ip", ip,
		)
	})
}
