package main

import (
	"os"
	"testing"
)

func TestResolveEnv(t *testing.T) {
	os.Setenv("SB_TEST_ADMIN", "xyz")
	defer os.Unsetenv("SB_TEST_ADMIN")

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain literal", "literal", "literal", false},
		{"env set", "env:SB_TEST_ADMIN", "xyz", false},
		// Missing var must fail loudly, never yield "" or "env:NAME".
		{"env unset", "env:SB_TEST_MISSING", "", true},
		{"empty value", "", "", false},
	}
	for _, c := range cases {
		got, err := resolveEnv("admin_token", c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: resolveEnv(%q) = %q, err %v; want %q, err %v", c.name, c.in, got, err, c.want, c.wantErr)
		}
	}
}
