package auth

import (
	"encoding/json"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestPersistedAuthChallengeTimesAreUnixMilliseconds(t *testing.T) {
	local := time.FixedZone("user-local", 8*60*60)
	expires := time.Date(2026, time.September, 25, 18, 0, 0, 123_000_000, local)
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID: "workspace-a", Provider: "oidc", State: "secret",
		RetryAt:   expires.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: expires.Format(time.RFC3339Nano),
		CreatedAt: expires.Add(-time.Hour).Format(time.RFC3339Nano),
	}
	raw, err := marshalPersistedAuthProviderChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		RetryAt   int64 `json:"retry_at"`
		ExpiresAt int64 `json:"expires_at"`
		CreatedAt int64 `json:"created_at"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("stored timestamps must be numbers: %v; payload=%s", err, raw)
	}
	if stored.RetryAt != expires.Add(-time.Minute).UnixMilli() || stored.ExpiresAt != expires.UnixMilli() || stored.CreatedAt != expires.Add(-time.Hour).UnixMilli() {
		t.Fatalf("stored times=%+v payload=%s", stored, raw)
	}
	restored, err := unmarshalPersistedAuthProviderChallenge(raw)
	if err != nil || restored.State != challenge.State || restored.ExpiresAt != expires.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}

func TestPersistedAuthSessionExpiryIsUnixMilliseconds(t *testing.T) {
	expires := time.Date(2026, time.September, 25, 10, 0, 0, 123_000_000, time.UTC)
	session := authmodel.AuthSession{WorkspaceID: "workspace-a", ExpiresAt: expires.Format(time.RFC3339Nano)}
	raw, err := marshalPersistedAuthSession(session)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || stored.ExpiresAt != expires.UnixMilli() {
		t.Fatalf("stored=%+v err=%v payload=%s", stored, err, raw)
	}
	restored, err := unmarshalPersistedAuthSession(raw)
	if err != nil || restored.ExpiresAt != session.ExpiresAt || restored.WorkspaceID != session.WorkspaceID {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}
