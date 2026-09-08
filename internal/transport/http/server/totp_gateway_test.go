package httpserver_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTOTPBrowserAndIdentityHTTPShareBindingWithoutLeakingSetupKey(t *testing.T) {
	server := newBrowserIdentityTestServer(t)
	token := ""
	request := func(path string, body map[string]any, expected int) map[string]any {
		t.Helper()
		payload, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Workspace-ID", "workspace-primary")
		req.Header.Set("Idempotency-Key", "totp-test-password-change")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != expected {
			t.Fatalf("%s status=%d want=%d code=%v", path, response.StatusCode, expected, result["code"])
		}
		if expected == http.StatusOK && strings.HasSuffix(path, "/auth/totp") && !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
			t.Fatal("TOTP response is cacheable")
		}
		return result
	}
	request("/browser/auth/totp", map[string]any{"operation": "status"}, http.StatusForbidden)
	login := request("/browser/auth/login", map[string]any{"workspace_id": "workspace-primary", "login": "admin@example.com", "password": "Domainry@2026"}, http.StatusOK)
	token, _ = login["access_token"].(string)
	if token == "" {
		t.Fatal("missing browser access token")
	}
	password := "Domainry@2026"
	if login["must_change_password"] == true {
		password = "VerifiedPassword@2026"
		changed := request("/browser/auth/change-password", map[string]any{"current_password": "Domainry@2026", "new_password": password}, http.StatusOK)
		token, _ = changed["access_token"].(string)
	}
	request("/browser/auth/totp", map[string]any{"operation": "status", "workspace_id": "other-workspace"}, http.StatusBadRequest)
	initial := request("/browser/auth/totp", map[string]any{"operation": "status"}, http.StatusOK)
	if initial["enabled"] != false {
		t.Fatal("unexpected existing binding")
	}
	enrollment := request("/browser/auth/totp", map[string]any{"operation": "enroll", "current_password": password}, http.StatusOK)
	secret, _ := enrollment["setup_key"].(string)
	if len(secret) != 32 {
		t.Fatal("invalid setup key length")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	code := func(step int64) string {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step))
		digest := hmac.New(sha1.New, key)
		_, _ = digest.Write(counter[:])
		sum := digest.Sum(nil)
		offset := sum[19] & 15
		return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
	}
	step := time.Now().Unix() / 30
	confirmed := request("/browser/auth/totp", map[string]any{"operation": "confirm", "state": enrollment["state"], "code": code(step)}, http.StatusOK)
	if confirmed["enabled"] != true || confirmed["setup_key"] != nil {
		t.Fatal("confirmation failed or repeated secret")
	}
	// The standalone endpoint sees the exact binding created through the SDK gateway.
	status := request("/auth/totp", map[string]any{"operation": "status"}, http.StatusOK)
	if status["enabled"] != true || status["setup_key"] != nil || status["otpauth_url"] != nil {
		t.Fatal("status does not share private binding state")
	}
	removed := request("/browser/auth/totp", map[string]any{"operation": "disable", "current_password": password, "code": code(step + 1)}, http.StatusOK)
	if removed["enabled"] != false {
		t.Fatal("verified removal failed")
	}
}
