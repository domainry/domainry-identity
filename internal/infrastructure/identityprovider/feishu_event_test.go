package identityprovider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func eventFixture(t *testing.T, p FeishuEventPolicy, event FeishuEvent, now time.Time) ([]byte, http.Header) {
	t.Helper()
	plain, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	key := sha256.Sum256([]byte(p.EncryptKey))
	block, _ := aes.NewCipher(key[:])
	frame := make([]byte, aes.BlockSize+len(plain))
	copy(frame, []byte("test-iv-123456789"))
	cipher.NewCBCEncrypter(block, frame[:aes.BlockSize]).CryptBlocks(frame[aes.BlockSize:], plain)
	body, _ := json.Marshal(map[string]string{"encrypt": base64.StdEncoding.EncodeToString(frame)})
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := "test-nonce"
	digest := sha256.Sum256(append([]byte(ts+nonce+p.EncryptKey), body...))
	header := http.Header{}
	header.Set("X-Lark-Request-Timestamp", ts)
	header.Set("X-Lark-Request-Nonce", nonce)
	header.Set("X-Lark-Signature", hex.EncodeToString(digest[:]))
	return body, header
}

func TestFeishuEventRequiresEncryptedSignedScopedFreshEvent(t *testing.T) {
	p := FeishuEventPolicy{Enabled: true, AppID: "test-app", TenantKey: "test-tenant", WorkspaceID: "workspace-primary", VerificationToken: "test-token", EncryptKey: "test-encryption-key"}
	now := time.Now().UTC()
	event := FeishuEvent{Schema: "2.0"}
	event.Header.EventID = "event-1"
	event.Header.EventType = "contact.user.deleted_v3"
	event.Header.Token = p.VerificationToken
	event.Header.AppID = p.AppID
	event.Header.TenantKey = p.TenantKey
	event.Event.Object.UnionID = "union-1"
	body, headers := eventFixture(t, p, event, now)
	if got, err := p.Verify(body, headers, now); err != nil || got.Event.Object.UnionID != "union-1" {
		t.Fatalf("valid event rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*FeishuEvent)
	}{
		{"wrong app", func(e *FeishuEvent) { e.Header.AppID = "other-app" }},
		{"wrong tenant", func(e *FeishuEvent) { e.Header.TenantKey = "other-tenant" }},
		{"wrong token", func(e *FeishuEvent) { e.Header.Token = "other-token" }},
		{"missing union", func(e *FeishuEvent) { e.Event.Object.UnionID = "" }},
		{"missing event id", func(e *FeishuEvent) { e.Header.EventID = "" }},
		{"wrong schema", func(e *FeishuEvent) { e.Schema = "1.0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := event
			test.mutate(&bad)
			raw, h := eventFixture(t, p, bad, now)
			if _, err := p.Verify(raw, h, now); err == nil {
				t.Fatal("unsafe event accepted")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte, http.Header) ([]byte, http.Header)
	}{
		{"forged signature", func(b []byte, h http.Header) ([]byte, http.Header) { h.Set("X-Lark-Signature", "forged"); return b, h }},
		{"missing signature", func(b []byte, h http.Header) ([]byte, http.Header) { h.Del("X-Lark-Signature"); return b, h }},
		{"tampered body", func(b []byte, h http.Header) ([]byte, http.Header) { return append(b, ' '), h }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, h := test.mutate(bytes.Clone(body), headers.Clone())
			if _, err := p.Verify(raw, h, now); err == nil {
				t.Fatal("unauthenticated event accepted")
			}
		})
	}
	if _, err := p.Verify(body, headers, now.Add(6*time.Minute)); err == nil {
		t.Fatal("stale delivery accepted")
	}
	if _, err := p.Verify(body, headers, now.Add(-6*time.Minute)); err == nil {
		t.Fatal("future delivery accepted")
	}
	plain, _ := json.Marshal(event)
	if _, err := p.Verify(plain, headers, now); err == nil {
		t.Fatal("plaintext accepted")
	}
	p.Enabled = false
	if _, err := p.Verify(body, headers, now); err == nil {
		t.Fatal("disabled integration accepted event")
	}
}

func TestFeishuChallengeRequiresEncryptedEnvelopeAndVerificationToken(t *testing.T) {
	p := FeishuEventPolicy{Enabled: true, AppID: "app", TenantKey: "tenant", WorkspaceID: "workspace-primary", VerificationToken: "token", EncryptKey: "encryption-key"}
	event := FeishuEvent{Type: "url_verification", Token: p.VerificationToken, Challenge: "opaque-challenge"}
	body, _ := eventFixture(t, p, event, time.Now())
	if got, err := p.Verify(body, http.Header{}, time.Now()); err != nil || got.Challenge != event.Challenge {
		t.Fatalf("challenge=%v err=%v", got, err)
	}
	event.Token = "wrong"
	body, _ = eventFixture(t, p, event, time.Now())
	if _, err := p.Verify(body, http.Header{}, time.Now()); err == nil {
		t.Fatal("wrong challenge token accepted")
	}
	for _, raw := range []string{`{}`, `{"encrypt":"bad"}`, `{"encrypt":"AAAAAAAAAAAAAAAAAAAAAA=="}`} {
		if _, err := p.Verify([]byte(raw), http.Header{}, time.Now()); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}
