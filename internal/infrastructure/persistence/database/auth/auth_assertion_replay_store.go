package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

func authAssertionReplayHash(workspaceID, provider, issuer, assertionID string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(workspaceID),
		strings.ToLower(strings.TrimSpace(provider)),
		strings.TrimSpace(issuer),
		strings.TrimSpace(assertionID),
	}, "\x00")))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s AuthStore) ClaimAuthAssertion(ctx context.Context, workspaceID, provider, issuer, assertionID string, expiresAt time.Time) (bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	provider, issuer, assertionID = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(issuer), strings.TrimSpace(assertionID)
	if provider == "" || issuer == "" || assertionID == "" || expiresAt.IsZero() {
		return false, nil
	}
	now := time.Now().UTC()
	if !expiresAt.After(now) {
		return false, nil
	}
	// Expired replay markers are only housekeeping. Correctness comes from the
	// unique replay hash and the fact that an active marker is never updated.
	_, _ = s.db.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier("auth_assertion_replays")+" WHERE "+s.store.Identifier("expires_at")+" <= "+s.store.Placeholder(1), now.Format(time.RFC3339Nano))
	replayHash := authAssertionReplayHash(workspaceID, provider, issuer, assertionID)
	_, err = s.db.ExecContext(ctx, "INSERT INTO "+s.store.TableIdentifier("auth_assertion_replays")+" ("+s.store.IdentityColumns("replay_hash", "workspace_id", "provider_key", "expires_at", "created_at")+") VALUES ("+s.store.Placeholders(5)+")", replayHash, workspaceID, provider, expiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		var existing int
		lookupErr := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+s.store.TableIdentifier("auth_assertion_replays")+" WHERE "+s.store.Identifier("replay_hash")+" = "+s.store.Placeholder(1), replayHash).Scan(&existing)
		if lookupErr == nil && existing > 0 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
