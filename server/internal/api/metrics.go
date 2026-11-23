package api

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/secblind/server/internal/store"
)

// Registry is this process's single Prometheus registry. Exposed so main.go
// can mount it on a dedicated metrics listener (never share the public bind).
var Registry = prometheus.NewRegistry()

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "http_requests_total", Help: "HTTP requests by route and status."},
		[]string{"route", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency by route.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route"},
	)
	authLoginTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "auth_login_total", Help: "Login attempts by outcome."},
		[]string{"result"}, // success|fail
	)
	authFailTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "auth_fail_total", Help: "Auth failures by reason."},
		[]string{"reason"},
	)
	licenseRevokedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "license_revoked_total", Help: "Admin revocations completed."},
	)
	licenseCreatedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "license_created_total", Help: "Admin license creations completed."},
	)
	rpcCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "rpc_calls_total", Help: "RPC calls by method and result."},
		[]string{"method", "result"},
	)
	heartbeatTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "heartbeat_total", Help: "Heartbeat requests received."},
	)
	sentinelAutobanTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "sentinel_autoban_total", Help: "licenses auto-banned after N sentinel trips"},
	)
	// legacyEvents keeps historical internal counters addressable without
	// renaming every callsite (hmac_fail, rpc_replay_blocked, etc.).
	legacyEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "sb_events_total", Help: "Internal signal counters."},
		[]string{"name", "endpoint"},
	)
	redisUp = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "redis_up", Help: "1 if last Redis PING succeeded."},
	)
	pgUp = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "pg_up", Help: "1 if last Postgres Ping succeeded."},
	)
)

func init() {
	Registry.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		authLoginTotal,
		authFailTotal,
		licenseRevokedTotal,
		licenseCreatedTotal,
		rpcCallsTotal,
		heartbeatTotal,
		sentinelAutobanTotal,
		legacyEvents,
		redisUp,
		pgUp,
	)
}

// metricInc is the legacy shim used by api.go/handlers — all historical
// `metricInc("name","/route")` calls land here.
func metricInc(name, endpoint string) {
	legacyEvents.WithLabelValues(name, endpoint).Inc()
}

// MetricsHandler returns an isolated handler serving /metrics from Registry.
// Mount it on a private bind — never on the public listener.
func MetricsHandler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
}

// StartHealthPolling launches a lightweight goroutine that updates redis_up /
// pg_up every `interval`. It stops when ctx is cancelled.
func StartHealthPolling(ctx context.Context, pg *store.PG, rdb *store.Redis, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			pollHealth(ctx, pg, rdb)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func pollHealth(ctx context.Context, pg *store.PG, rdb *store.Redis) {
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if pg != nil && pg.Pool != nil {
		if err := pg.Pool.Ping(pingCtx); err == nil {
			pgUp.Set(1)
		} else {
			pgUp.Set(0)
		}
	}
	if rdb != nil && rdb.C != nil {
		if err := rdb.C.Ping(pingCtx).Err(); err == nil {
			redisUp.Set(1)
		} else {
			redisUp.Set(0)
		}
	}
}
