package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetricsHandler confirms /metrics returns 200 and advertises the core
// counters the ops team scrapes.
func TestMetricsHandler(t *testing.T) {
	// Force at least one sample per vector so each counter appears in output
	// (Prometheus only emits a label combination after it has been observed).
	httpRequestsTotal.WithLabelValues("/_test", "200").Inc()
	authLoginTotal.WithLabelValues("success").Inc()
	rpcCallsTotal.WithLabelValues("ping", "ok").Inc()

	srv := httptest.NewServer(MetricsHandler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		"http_requests_total",
		"auth_login_total",
		"rpc_calls_total",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("metric %q not in response", want)
		}
	}
}
