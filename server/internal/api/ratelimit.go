package api

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RouteLimit sets token-bucket params per route.
type RouteLimit struct {
	RPS   float64
	Burst int
}

// RouteLimits maps route key (short name, not path) to limits.
// Keys the server uses: auth_challenge, auth_login, heartbeat,
// payload_fetch, rpc_call, admin_revoke.
type RouteLimits map[string]RouteLimit

// routeKeyForPath maps a URL path to its config key.
var routeKeyForPath = map[string]string{
	"/api/v1/auth/challenge":   "auth_challenge",
	"/api/v1/auth/login":       "auth_login",
	"/api/v1/session/heartbeat": "heartbeat",
	"/api/v1/payload/fetch":    "payload_fetch",
	"/api/v1/rpc/call":         "rpc_call",
	"/api/v1/admin/revoke":     "admin_revoke",
}

// limiterBucket holds the per-(route,ip) limiter and its last-seen time
// so we can evict cold entries.
type limiterBucket struct {
	l    *rate.Limiter
	seen time.Time
}

// routeLimiter is in-process; single-instance deploy. For horizontal scale,
// swap Allow() to a Redis token-bucket script. shortcut: single-instance only,
// upgrade when scaling out.
type routeLimiter struct {
	cfg RouteLimits
	mu  sync.Mutex
	m   map[string]*limiterBucket // key: route + "|" + ip
}

func newRouteLimiter(cfg RouteLimits) *routeLimiter {
	rl := &routeLimiter{cfg: cfg, m: map[string]*limiterBucket{}}
	go rl.gcLoop()
	return rl
}

// Allow returns true if the (route, ip) bucket admits one more event.
// Unknown routes pass through (no limit).
func (rl *routeLimiter) Allow(route, ip string) bool {
	cfg, ok := rl.cfg[route]
	if !ok || cfg.RPS <= 0 || cfg.Burst <= 0 {
		return true
	}
	key := route + "|" + ip
	rl.mu.Lock()
	b, ok := rl.m[key]
	if !ok {
		b = &limiterBucket{l: rate.NewLimiter(rate.Limit(cfg.RPS), cfg.Burst)}
		rl.m[key] = b
	}
	b.seen = time.Now()
	lim := b.l
	rl.mu.Unlock()
	return lim.Allow()
}

// gcLoop evicts buckets unused for >10 min. Prevents unbounded growth under
// IP churn (DoS vector).
func (rl *routeLimiter) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		rl.mu.Lock()
		for k, b := range rl.m {
			if b.seen.Before(cutoff) {
				delete(rl.m, k)
			}
		}
		rl.mu.Unlock()
	}
}

// packageRouteLimiter is loaded by main.go; observe() reads it.
var packageRouteLimiter atomic_RouteLimiter

type atomic_RouteLimiter struct {
	p *routeLimiter
	mu sync.RWMutex
}

func (a *atomic_RouteLimiter) load() *routeLimiter {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.p
}

func (a *atomic_RouteLimiter) store(p *routeLimiter) {
	a.mu.Lock()
	a.p = p
	a.mu.Unlock()
}

// SetRouteLimits installs the per-route limiter. main.go calls this at startup.
func SetRouteLimits(cfg RouteLimits) {
	packageRouteLimiter.store(newRouteLimiter(cfg))
}
