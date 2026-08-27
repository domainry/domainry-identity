package auth

import (
	"net/http/httptest"
	"testing"
)

func TestBearerTokenRejectsLongNonBearerAuthorization(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Basic abcdefghijklmnopqrstuvwxyz")
	if token := bearerTokenFromRequest(request); token != "" {
		t.Fatalf("non-bearer token = %q", token)
	}
}
