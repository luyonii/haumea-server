package api

import (
	"net"
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	saved := trustedProxyNets
	t.Cleanup(func() { trustedProxyNets = saved })

	nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	trustedProxyNets = nets

	mk := func(remote, xff string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	cases := []struct {
		name, remote, xff, want string
	}{
		{"no_xff_with_port", "203.0.113.5:1234", "", "203.0.113.5"},
		{"no_xff_no_port", "203.0.113.5", "", "203.0.113.5"},
		{"xff_from_trusted_single", "10.1.2.3:9000", "198.51.100.7", "198.51.100.7"},
		{"xff_from_trusted_chain_takes_last", "10.1.2.3:9000", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		{"xff_from_trusted_invalid_falls_back", "10.1.2.3:9000", "not-an-ip", "10.1.2.3"},
		{"xff_from_untrusted_ignored", "203.0.113.5:1234", "198.51.100.7", "203.0.113.5"},
		{"xff_from_trusted_ipv6", "[::1]:443", "2001:db8::1", "2001:db8::1"},
		{"unparseable_remote_returned_verbatim", "garbage", "198.51.100.7", "garbage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clientIP(mk(c.remote, c.xff))
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1", "", "  ::1  "})
	if err != nil {
		t.Fatalf("ok case: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("len=%d want 3", len(nets))
	}
	if !nets[1].Contains(net.ParseIP("127.0.0.1")) {
		t.Fatalf("127.0.0.1 not contained")
	}
	if _, err := parseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatalf("expected error for bad entry")
	}
}

// TestProxyAssertsHTTPS covers the require_https gate: X-Forwarded-Proto is
// trusted ONLY from a trusted proxy, so a direct attacker on the plain bind
// cannot forge https even with the header set.
func TestProxyAssertsHTTPS(t *testing.T) {
	saved := trustedProxyNets
	t.Cleanup(func() { trustedProxyNets = saved })
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	trustedProxyNets = nets

	mk := func(remote, xfp string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		return r
	}
	cases := []struct {
		name, remote, xfp string
		want              bool
	}{
		{"trusted_https", "10.1.2.3:9000", "https", true},
		{"trusted_https_mixed_case", "10.1.2.3:9000", "HTTPS", true},
		{"trusted_http", "10.1.2.3:9000", "http", false},
		{"trusted_no_header", "10.1.2.3:9000", "", false},
		{"untrusted_forged_https", "203.0.113.5:1234", "https", false},
		{"unparseable_remote", "garbage", "https", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := proxyAssertsHTTPS(mk(c.remote, c.xfp)); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}
