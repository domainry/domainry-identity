package service

import (
	"testing"
	"time"
)

func TestRefreshTokenExpiration(t *testing.T) {
	if !tokenExpired("invalid") {
		t.Fatal("invalid expiration must be expired")
	}
	if !tokenExpired(time.Now().Add(-time.Minute).Format(time.RFC3339)) {
		t.Fatal("past expiration must be expired")
	}
	if tokenExpired(time.Now().Add(time.Hour).Format(time.RFC3339)) {
		t.Fatal("future expiration must remain active")
	}
}

func TestBearerTokenParsing(t *testing.T) {
	for _, authorization := range []string{"", "token", "Basic token", "Bearer token extra"} {
		if token := bearerToken(authorization); token != "" {
			t.Fatalf("authorization %q unexpectedly produced %q", authorization, token)
		}
	}
	if token := bearerToken("  bEaReR   token-value  "); token != "token-value" {
		t.Fatalf("unexpected bearer token %q", token)
	}
}
