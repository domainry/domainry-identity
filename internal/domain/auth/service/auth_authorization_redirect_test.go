package service

import "testing"

func TestAuthorizationRedirectURLSupportsRegisteredHTTPHosts(t *testing.T) {
	for _, callback := range []string{
		"http://116.6.111.254:18080/auth/callback",
		"http://192.168.98.11:8081/auth/callback",
		"http://knowledge.internal/auth/callback",
		"http://127.0.0.1:8080/auth/callback",
		"https://enterprise.example/auth/callback",
	} {
		if !validAuthorizationRedirectURL(callback) {
			t.Errorf("rejected registered callback syntax %q", callback)
		}
	}
	for _, callback := range []string{
		"http://user:password@116.6.111.254:18080/auth/callback",
		"http://116.6.111.254:18080/auth/callback#fragment",
		"http:///auth/callback", "https:///auth/callback", "javascript:alert(1)", "/auth/callback",
	} {
		if validAuthorizationRedirectURL(callback) {
			t.Errorf("accepted invalid callback %q", callback)
		}
	}
}
