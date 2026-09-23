package identity_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityAuthoringRepositoryUsesSharedLeasedOperations(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "authoring-operations.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := identitypersistence.NewIdentityAuthoringRepository(store)
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	candidate := identityauthoring.Receipt{
		ID: "authoring-1", WorkspaceID: "workspace-primary", UseCase: "identity.roles.update",
		ResourceType: "identity_role", TargetID: "role-1", ActorID: "admin-1",
		IdempotencyKey: "authoring-key", RequestFingerprint: "fingerprint-1", Status: idempotency.StatusProcessing,
		LeaseOwner: "worker-1", LeaseExpiresAt: now.Add(time.Second), FencingToken: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := repository.Claim(t.Context(), candidate, time.Second); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound shared Operations error=%v", err)
	}
	bindSharedOperations(t, store)
	claim, err := repository.Claim(t.Context(), candidate, time.Second)
	if err != nil || claim.Decision != idempotency.DecisionAcquired {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	inProgress, err := repository.Claim(t.Context(), candidate, time.Second)
	if err != nil || inProgress.Decision != idempotency.DecisionInProgress {
		t.Fatalf("in-progress=%#v err=%v", inProgress, err)
	}
	conflictCandidate := candidate
	conflictCandidate.RequestFingerprint = "fingerprint-2"
	conflict, err := repository.Claim(t.Context(), conflictCandidate, time.Second)
	if err != nil || conflict.Decision != idempotency.DecisionFingerprintConflict {
		t.Fatalf("conflict=%#v err=%v", conflict, err)
	}
	reclaimCandidate := candidate
	reclaimCandidate.LeaseOwner = "worker-2"
	reclaimCandidate.UpdatedAt = now.Add(2 * time.Second)
	reclaimed, err := repository.Claim(t.Context(), reclaimCandidate, time.Second)
	if err != nil || reclaimed.Decision != idempotency.DecisionAcquired || reclaimed.Receipt.FencingToken != 2 {
		t.Fatalf("reclaimed=%#v err=%v", reclaimed, err)
	}
	if _, err := repository.Complete(t.Context(), identityauthoring.Completion{
		ReceiptID: candidate.ID, WorkspaceID: candidate.WorkspaceID, LeaseOwner: candidate.LeaseOwner,
		FencingToken: candidate.FencingToken, Status: idempotency.StatusSucceeded, Result: []byte(`{"ok":true}`), CompletedAt: now.Add(3 * time.Second),
	}); !errors.Is(err, identityauthoring.ErrLeaseLost) {
		t.Fatalf("stale authoring completion error=%v", err)
	}
	completed, err := repository.Complete(t.Context(), identityauthoring.Completion{
		ReceiptID: reclaimed.Receipt.ID, WorkspaceID: reclaimed.Receipt.WorkspaceID, LeaseOwner: reclaimed.Receipt.LeaseOwner,
		FencingToken: reclaimed.Receipt.FencingToken, Status: idempotency.StatusSucceeded, Result: []byte(`{"ok":true}`), CompletedAt: now.Add(3 * time.Second),
	})
	if err != nil || completed.Status != idempotency.StatusSucceeded {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	replay, err := repository.Claim(t.Context(), reclaimCandidate, time.Second)
	if err != nil || replay.Decision != idempotency.DecisionReplay {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	var operationCount, legacyTableCount int
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id='workspace-primary' AND owner='identity' AND kind='identity.authoring' AND idempotency_key='authoring-key' AND status='succeeded' AND fencing_token=2`).Scan(&operationCount); err != nil || operationCount != 1 {
		t.Fatalf("shared authoring operation count=%d err=%v", operationCount, err)
	}
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_authoring_receipts'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy authoring receipt table count=%d err=%v", legacyTableCount, err)
	}
}
