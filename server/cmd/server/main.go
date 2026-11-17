// TLS: server listens plain HTTP on 0.0.0.0:8080 behind an nginx TLS terminator.
// Production MUST bind 127.0.0.1 only + firewall rule blocking 0.0.0.0:8080,
// OR reject requests where X-Forwarded-Proto != https.
// Current dev config is for the integration harness only.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/secblind/server/internal/api"
	"github.com/secblind/server/internal/store"
)

type config struct {
	Listen        string `yaml:"listen"`
	PostgresDSN   string `yaml:"postgres_dsn"`
	RedisAddr     string `yaml:"redis_addr"`
	MasterSecret  string `yaml:"master_secret"`   // hex, or "env:NAME"
	SessionTTLS   int    `yaml:"session_ttl_s"`
	HeartbeatS    int    `yaml:"heartbeat_s"`
	HWIDCooldownD int    `yaml:"hwid_cooldown_d"`
	Rate          struct {
		PerIPRPM        int `yaml:"per_ip_rpm"`
		PerHWIDRPM      int `yaml:"per_hwid_rpm"`
		PerHWIDRPMFetch int `yaml:"per_hwid_rpm_payload_fetch"`
	} `yaml:"rate"`
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

func resolveSecret(v string) ([]byte, error) {
	if strings.HasPrefix(v, "env:") {
		v = os.Getenv(v[4:])
	}
	return hex.DecodeString(v)
}

func main() {
	path := "config.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	master, err := resolveSecret(cfg.MasterSecret)
	if err != nil || len(master) < 32 {
		log.Fatalf("master_secret must be hex of at least 32 bytes")
	}

	ctx := context.Background()
	pg, err := store.OpenPG(ctx, cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer pg.Close()
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	err = pg.Pool.Ping(pingCtx)
	pingCancel()
	if err != nil {
		log.Fatalf("postgres unreachable: %v", err)
	}

	rdb := store.OpenRedis(cfg.RedisAddr)
	defer rdb.Close()

	apiCfg := api.Config{
		MasterSecret:      master,
		SessionTTL:        time.Duration(cfg.SessionTTLS) * time.Second,
		HeartbeatInterval: cfg.HeartbeatS,
		HWIDCooldown:      time.Duration(cfg.HWIDCooldownD) * 24 * time.Hour,
		RatePerIP:         cfg.Rate.PerIPRPM,
		RatePerHWID:       cfg.Rate.PerHWIDRPM,
		RatePerHWIDFetch:  cfg.Rate.PerHWIDRPMFetch,
	}
	srv := api.New(pg, rdb, apiCfg)

	mux := http.NewServeMux()
	srv.Register(mux)

	addr := cfg.Listen
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv.LogStartup(addr)

	hs := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	// shortcut: plain HTTP. Terminate TLS at Nginx. Upgrade when running standalone.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()

	select {
	case err := <-errc:
		// Close pools explicitly so Fatalf-less exit still flushes resources
		// (defers would run, but Fatalf skips them — close first, then fatal).
		rdb.Close()
		pg.Close()
		log.Fatalf("listen: %v", err)
	case s := <-sig:
		log.Printf("signal %v: shutting down (30s drain)", s)
	}

	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("shutdown: %v", err)
	}
	// pg/rdb closed by the defers above, after the drain.
	log.Printf("bye")
}
