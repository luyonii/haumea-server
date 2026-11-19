package main

import (
	"os"
	"testing"
)

func TestResolveEnvAdminFields(t *testing.T) {
	os.Setenv("SB_TEST_ADMIN", "xyz")
	defer os.Unsetenv("SB_TEST_ADMIN")

	got, err := resolveEnv("admin_token", "env:SB_TEST_ADMIN")
	if err != nil || got != "xyz" {
		t.Fatalf("env indirection: got %q err %v", got, err)
	}
	if got, err := resolveEnv("admin_token", "literal"); err != nil || got != "literal" {
		t.Fatalf("literal passthrough: got %q err %v", got, err)
	}
	// Missing var must fail loudly, never yield "" or "env:NAME".
	if got, err := resolveEnv("admin_token", "env:SB_TEST_MISSING"); err == nil || got != "" {
		t.Fatalf("missing var: got %q err %v", got, err)
	}
}
