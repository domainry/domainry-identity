package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	ormbuilder "github.com/domainry/domainry-orm/builder"
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
	deleteStatement, deleteArgs, deleteBuildErr := ormbuilder.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "auth_assertion_replays", workspaceID).
		Where(ormbuilder.LessThanOrEqual("expires_at", now.Format(time.RFC3339Nano))).Build()
	if deleteBuildErr == nil {
		_, _ = s.db.ExecContext(ctx, deleteStatement, deleteArgs...)
	}
	replayHash := authAssertionReplayHash(workspaceID, provider, issuer, assertionID)
	insertStatement, insertArgs, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "auth_assertion_replays", workspaceID).
		Columns("replay_hash", "provider_key", "expires_at", "created_at").
		Values(replayHash, provider, expiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Build()
	if buildErr != nil {
		return false, buildErr
	}
	_, err = s.db.ExecContext(ctx, insertStatement, insertArgs...)
	if err != nil {
		var existing int
		lookupStatement, lookupArgs, lookupBuildErr := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_assertion_replays", workspaceID).
			Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("replay_hash", replayHash)).Build()
		if lookupBuildErr != nil {
			return false, lookupBuildErr
		}
		lookupErr := s.db.QueryRowContext(ctx, lookupStatement, lookupArgs...).Scan(&existing)
		if lookupErr == nil && existing > 0 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
