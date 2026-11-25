// TLS: server listens plain HTTP on 0.0.0.0:8080 behind an nginx TLS terminator.
// Production MUST bind 127.0.0.1 only + firewall rule blocking 0.0.0.0:8080,
// OR reject requests where X-Forwarded-Proto != https.
// Current dev config is for the integration harness only.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/secblind/server/internal/admin_ui"
	"github.com/secblind/server/internal/api"
	"github.com/secblind/server/internal/store"
)

type rateRoute struct {
	RPS   float64 `yaml:"rps"`
	Burst int     `yaml:"burst"`
}

type config struct {
	Listen        string `yaml:"listen"`
	MetricsAddr   string `yaml:"metrics_addr"` // separate private bind for Prometheus /metrics
	AdminAddr     string `yaml:"admin_addr"`   // separate private bind for /api/v1/admin/*
	AdminToken    string `yaml:"admin_token"`  // required to enable admin endpoint; empty = disabled
	PostgresDSN   string `yaml:"postgres_dsn"`
	RedisAddr     string `yaml:"redis_addr"`
	MasterSecret  string `yaml:"master_secret"` // hex, or "env:NAME"
	SessionTTLS   int    `yaml:"session_ttl_s"`
	HeartbeatS    int    `yaml:"heartbeat_s"`
	HWIDCooldownD int    `yaml:"hwid_cooldown_d"`
	Rate          struct {
		PerIPRPM        int `yaml:"per_ip_rpm"`
		PerHWIDRPM      int `yaml:"per_hwid_rpm"`
		PerHWIDRPMFetch int `yaml:"per_hwid_rpm_payload_fetch"`
	} `yaml:"rate"`
	// Per-route token-bucket limits; keys match ratelimit.go's routeKeyForPath.
	RateLimits map[string]rateRoute `yaml:"rate_limits"`

	// Logging — JSON + lumberjack file rotation.
	LogFile       string `yaml:"log_file"`
	LogMaxSizeMB  int    `yaml:"log_max_size_mb"`
	LogMaxBackups int    `yaml:"log_max_backups"`
	LogMaxAgeDays int    `yaml:"log_max_age_days"`
	LogCompress   bool   `yaml:"log_compress"`
	LogDev        bool   `yaml:"log_dev"` // true -> console encoder + debug level

	TrustedProxies []string `yaml:"trusted_proxies"`
	EnableDebug    bool     `yaml:"enable_debug"`
	DebugToken     string   `yaml:"debug_token"`
	RequireHTTPS   bool     `yaml:"require_https"`
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// resolveEnv expands a value of the form "env:NAME" from the environment.
// A missing or empty variable is a hard error: a secret must never silently
// degrade to "" (or to the literal "env:NAME") at startup.
func resolveEnv(field, v string) (string, error) {
	if !strings.HasPrefix(v, "env:") {
		return v, nil
	}
	name := v[4:]
	got := os.Getenv(name)
	if got == "" {
		return "", fmt.Errorf("%s: env var %s is unset or empty", field, name)
	}
	return got, nil
}

func resolveSecret(field, v string) ([]byte, error) {
	s, err := resolveEnv(field, v)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

// buildBinaryBindSalt turns the two expected-binary-integrity env values into
// the 12-byte salt suffix LE32(text_crc32) || LE64(code_fingerprint). Both are
// required: an empty value is a hard startup error (fail closed), matching the
// secret-resolution policy. crcHex is 8 hex chars (uint32); fpHex is up to 16
// hex chars (uint64, the uint32 client fingerprint zero-extended).
func buildBinaryBindSalt(crcHex, fpHex string) ([]byte, error) {
	crcHex = strings.TrimSpace(crcHex)
	fpHex = strings.TrimSpace(fpHex)
	if crcHex == "" {
		return nil, fmt.Errorf("SECBLIND_EXPECTED_TEXT_CRC32 is unset or empty")
	}
	if fpHex == "" {
		return nil, fmt.Errorf("SECBLIND_EXPECTED_CODE_FINGERPRINT is unset or empty")
	}
	crc, err := strconv.ParseUint(crcHex, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("SECBLIND_EXPECTED_TEXT_CRC32: %w", err)
	}
	fp, err := strconv.ParseUint(fpHex, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("SECBLIND_EXPECTED_CODE_FINGERPRINT: %w", err)
	}
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], uint32(crc))
	binary.LittleEndian.PutUint64(b[4:12], fp)
	return b, nil
}

func toRouteLimits(in map[string]rateRoute) api.RouteLimits {
	out := api.RouteLimits{}
	for k, v := range in {
		out[k] = api.RouteLimit{RPS: v.RPS, Burst: v.Burst}
	}
	return out
}

func main() {
	path := "config.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	cfg, err := loadConfig(path)
	if err != nil {
		// No logger yet; stderr is fine.
		os.Stderr.WriteString("config: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Logger first so every subsequent event flows through zap + lumberjack.
	logger, closeLog := api.InitLogger(api.LogConfig{
		Dev:        cfg.LogDev,
		File:       cfg.LogFile,
		MaxSizeMB:  cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAgeDays: cfg.LogMaxAgeDays,
		Compress:   cfg.LogCompress,
	})
	api.SetLogger(logger)
	store.Logf = func(format string, args ...any) { logger.Warnf(format, args...) }
	defer closeLog()

	// Every sensitive field goes through the same "env:NAME" resolution, so a
	// config documenting env: indirection never ships as a literal credential.
	for _, f := range []struct {
		name string
		p    *string
	}{
		{"admin_token", &cfg.AdminToken},
		{"debug_token", &cfg.DebugToken},
		{"postgres_dsn", &cfg.PostgresDSN},
		{"redis_addr", &cfg.RedisAddr},
	} {
		v, err := resolveEnv(f.name, *f.p)
		if err != nil {
			logger.Fatal(err.Error())
		}
		*f.p = v
	}

	master, err := resolveSecret("master_secret", cfg.MasterSecret)
	if err != nil {
		logger.Fatalf("master_secret: %v", err)
	}
	if len(master) < 32 {
		logger.Fatal("master_secret must be hex of at least 32 bytes")
	}

	// Binary-integrity binding (audit items #1/#10). The expected .text CRC32
	// and code fingerprint of the shipped client are folded into the /auth/login
	// HKDF salt. Fail closed: both must be present at startup, or a mismatched
	// client could still authenticate.
	bindSalt, err := buildBinaryBindSalt(
		os.Getenv("SECBLIND_EXPECTED_TEXT_CRC32"),
		os.Getenv("SECBLIND_EXPECTED_CODE_FINGERPRINT"))
	if err != nil {
		logger.Fatalf("binary bind: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pg, err := store.OpenPG(ctx, cfg.PostgresDSN)
	if err != nil {
		logger.Fatalf("postgres: %v", err)
	}
	defer pg.Close()
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	err = pg.Pool.Ping(pingCtx)
	pingCancel()
	if err != nil {
		logger.Fatalf("postgres unreachable: %v", err)
	}

	rdb := store.OpenRedis(cfg.RedisAddr)
	defer rdb.Close()

	apiCfg := api.Config{
		MasterSecret:      master,
		BinaryBindSalt:    bindSalt,
		SessionTTL:        time.Duration(cfg.SessionTTLS) * time.Second,
		HeartbeatInterval: cfg.HeartbeatS,
		HWIDCooldown:      time.Duration(cfg.HWIDCooldownD) * 24 * time.Hour,
		RatePerIP:         cfg.Rate.PerIPRPM,
		RatePerHWID:       cfg.Rate.PerHWIDRPM,
		RatePerHWIDFetch:  cfg.Rate.PerHWIDRPMFetch,
		TrustedProxies:    cfg.TrustedProxies,
		EnableDebug:       cfg.EnableDebug,
		DebugToken:        cfg.DebugToken,
		RequireHTTPS:      cfg.RequireHTTPS,
	}
	srv := api.New(pg, rdb, apiCfg)

	// Per-route rate limiter (in-process token bucket).
	api.SetRouteLimits(toRouteLimits(cfg.RateLimits))

	// Background health polling updates pg_up / redis_up gauges.
	api.StartHealthPolling(ctx, pg, rdb, 10*time.Second)

	publicMux := http.NewServeMux()
	srv.Register(publicMux)

	addr := cfg.Listen
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv.LogStartup(addr)

	hs := &http.Server{
		Addr:              addr,
		Handler:           publicMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	// shortcut: plain HTTP. Terminate TLS at Nginx. Upgrade when running standalone.

	// Metrics listener (isolated from the public bind).
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", api.MetricsHandler())
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mmux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Infow("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Errorf("metrics listen: %v", err)
			}
		}()
	}

	// Admin listener (also private). Bind to loopback only; reach it from a
	// workstation via `ssh -L 8443:127.0.0.1:8443 user@vps`. A 0.0.0.0 bind
	// on this port would expose the JSON admin endpoints and the dashboard
	// to anyone who can see the host.
	var adminSrv *http.Server
	if cfg.AdminAddr != "" && cfg.AdminToken != "" {
		amux := http.NewServeMux()
		srv.RegisterAdmin(amux, cfg.AdminToken)
		admin_ui.Register(amux, cfg.AdminToken)
		adminSrv = &http.Server{
			Addr:              cfg.AdminAddr,
			Handler:           amux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			logger.Infow("admin listening", "addr", cfg.AdminAddr)
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Errorf("admin listen: %v", err)
			}
		}()
	} else if cfg.AdminAddr != "" || cfg.AdminToken != "" {
		logger.Warnw("admin endpoint disabled: both admin_addr and admin_token required")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()

	select {
	case err := <-errc:
		rdb.Close()
		pg.Close()
		logger.Fatalf("listen: %v", err)
	case s := <-sig:
		logger.Infow("signal received: shutting down (30s drain)", "signal", s.String())
	}

	sctx, scancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer scancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Warnf("shutdown: %v", err)
	}
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(sctx)
	}
	if adminSrv != nil {
		_ = adminSrv.Shutdown(sctx)
	}
	logger.Info("bye")
}
