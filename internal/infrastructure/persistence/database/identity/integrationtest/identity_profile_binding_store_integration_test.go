package identity_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityProfileBindingStoreProvidesAtomicOptimisticIdempotentLifecycle(t *testing.T) {
	identityStore, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "profile-binding.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	var retiredEvents int
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_profile_binding_events'`).Scan(&retiredEvents); err != nil || retiredEvents != 0 {
		t.Fatalf("retired profile binding event table count=%d err=%v", retiredEvents, err)
	}
	unboundSQLStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := identitypersistence.NewIdentityProfileBindingStore(unboundSQLStore).GetIdentityProfileBindingReceipt(t.Context(), profileBindingMutation("member-1", identitymodel.IdentityProfileBindingInvite, "", 0, "unbound")); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound shared Operations error=%v", err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE TABLE member_profile (
		workspace_id TEXT NOT NULL,
		id TEXT PRIMARY KEY,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		identity_user TEXT,
		email TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `CREATE UNIQUE INDEX uniq_member_profile_user ON member_profile (workspace_id, identity_user)`); err != nil {
		t.Fatal(err)
	}
	for _, profileID := range []string{"member-1", "member-2"} {
		if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO member_profile (workspace_id, id, created_at, updated_at, identity_user, email) VALUES ('workspace-primary', ?, 'now', 'now', NULL, ?)`, profileID, profileID+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	store := identitypersistence.NewIdentityProfileBindingStore(identitySQLStoreForProfileBindingTest(t, identityStore))
	if _, err := identityStore.DB().ExecContext(t.Context(), `INSERT INTO member_profile (workspace_id, id, created_at, updated_at, identity_user, email) VALUES ('workspace-primary', 'member-seeded', 'now', 'now', 'seed-user', 'seed@example.com')`); err != nil {
		t.Fatal(err)
	}
	adopted, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), profileBindingMutation("member-seeded", identitymodel.IdentityProfileBindingBind, "seed-user", 0, "adopt-seed"))
	if err != nil || adopted.Binding.Status != identitymodel.IdentityProfileBindingActive || adopted.Binding.IdentityUserID != "seed-user" || adopted.Binding.Version != 1 {
		t.Fatalf("adopted=%#v err=%v", adopted, err)
	}
	loadedAdopted, found, err := store.GetIdentityProfileBinding(t.Context(), "workspace-primary", "member_profile", "member-seeded")
	if err != nil || !found || loadedAdopted.IdentityUserID != "seed-user" {
		t.Fatalf("loaded adopted=%#v found=%v err=%v", loadedAdopted, found, err)
	}
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), profileBindingMutation("member-seeded", identitymodel.IdentityProfileBindingBind, "other-user", 1, "replace-seed")); apperror.CodeOf(err) != "backend.identity.profile_already_bound" {
		t.Fatalf("adopted binding allowed a bind-style replacement: %v", err)
	}
	mutation := profileBindingMutation("member-1", identitymodel.IdentityProfileBindingInvite, "", 0, "invite-1")
	mutation.InvitationChannel = "email"
	mutation.CausationID = "cause-invite-1"
	invited, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation)
	if err != nil || invited.Binding.Status != identitymodel.IdentityProfileBindingInvited || invited.Binding.Version != 1 {
		t.Fatalf("invited=%#v err=%v", invited, err)
	}
	replayed, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation)
	if err != nil || !replayed.Replayed || replayed.ID != invited.ID {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	reused := mutation
	reused.RequestFingerprint = "different"
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("reused key error=%v", err)
	}

	claimedMutation := profileBindingMutation("member-1", identitymodel.IdentityProfileBindingClaim, "user-1", 1, "claim-1")
	claimedMutation.ClaimProofType = "email"
	claimedMutation.SystemManagedRoleIDs = []string{"member-role"}
	claimed, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), claimedMutation)
	if err != nil || claimed.Binding.Status != identitymodel.IdentityProfileBindingActive || claimed.Binding.IdentityUserID != "user-1" || claimed.Binding.Version != 2 {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	assertProfileBindingRecordUser(t, identityStore, "member-1", "user-1")
	assertProfileBindingRole(t, identityStore, "user-1", "member-role", "active", "member", "member-1")
	loaded, found, err := store.GetIdentityProfileBinding(t.Context(), "workspace-primary", "member_profile", "member-1")
	if err != nil || !found || loaded.Version != 2 {
		t.Fatalf("loaded=%#v found=%v err=%v", loaded, found, err)
	}
	events, err := store.ListIdentityProfileBindingEvents(t.Context(), "workspace-primary", "member_profile", "member-1")
	if err != nil || len(events) != 2 || events[0].OperationID != invited.ID || events[0].CausationID != "cause-invite-1" || events[1].Operation != identitymodel.IdentityProfileBindingClaim || events[1].Status != "pending" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	var auditEvents int
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id=? AND object_key=? AND record_id=? AND event IN (?, ?)`, "workspace-primary", "member_profile", "member-1", "identity.profile_binding.invite", "identity.profile_binding.claim").Scan(&auditEvents); err != nil || auditEvents != 2 {
		t.Fatalf("profile binding audit events=%d err=%v", auditEvents, err)
	}

	conflicting := profileBindingMutation("member-2", identitymodel.IdentityProfileBindingBind, "user-1", 0, "bind-conflict")
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), conflicting); apperror.CodeOf(err) != "backend.identity.profile_binding_conflict" {
		t.Fatalf("duplicate identity binding error=%v", err)
	}
	assertProfileBindingRecordUser(t, identityStore, "member-2", "")
	if _, found, err := store.GetIdentityProfileBinding(t.Context(), "workspace-primary", "member_profile", "member-2"); err != nil || found {
		t.Fatalf("failed transaction persisted binding: found=%v err=%v", found, err)
	}

	rebind := profileBindingMutation("member-1", identitymodel.IdentityProfileBindingRebind, "user-2", 2, "rebind-1")
	rebind.Reason = "account ownership corrected"
	rebind.SystemManagedRoleIDs = []string{"member-role"}
	rebound, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), rebind)
	if err != nil || rebound.Binding.IdentityUserID != "user-2" || rebound.Binding.Version != 3 {
		t.Fatalf("rebound=%#v err=%v", rebound, err)
	}
	assertProfileBindingRole(t, identityStore, "user-1", "member-role", "revoked", "member", "member-1")
	assertProfileBindingRole(t, identityStore, "user-2", "member-role", "active", "member", "member-1")
	reboundReplay, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), rebind)
	if err != nil || !reboundReplay.Replayed || reboundReplay.ID != rebound.ID {
		t.Fatalf("rebind replay=%#v err=%v", reboundReplay, err)
	}
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), profileBindingMutation("member-1", identitymodel.IdentityProfileBindingUnlink, "", 2, "stale")); apperror.CodeOf(err) != "backend.identity.profile_binding_version_conflict" {
		t.Fatalf("stale version error=%v", err)
	}
	unlinkMutation := profileBindingMutation("member-1", identitymodel.IdentityProfileBindingUnlink, "", 3, "unlink-1")
	unlinkMutation.SystemManagedRoleIDs = []string{"member-role"}
	unlinked, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), unlinkMutation)
	if err != nil || unlinked.Binding.Status != identitymodel.IdentityProfileBindingUnlinked || unlinked.Binding.IdentityUserID != "" || unlinked.Binding.Version != 4 {
		t.Fatalf("unlinked=%#v err=%v", unlinked, err)
	}
	assertProfileBindingRecordUser(t, identityStore, "member-1", "")
	assertProfileBindingRole(t, identityStore, "user-2", "member-role", "revoked", "member", "member-1")
	unlinkedReplay, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), unlinkMutation)
	if err != nil || !unlinkedReplay.Replayed || unlinkedReplay.ID != unlinked.ID {
		t.Fatalf("unlink replay=%#v err=%v", unlinkedReplay, err)
	}
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), profileBindingMutation("member-1", identitymodel.IdentityProfileBindingUnlink, "", 4, "unlink-2")); apperror.CodeOf(err) != "backend.identity.profile_not_bound" {
		t.Fatalf("duplicate unlink error=%v", err)
	}
	var operationCount, legacyTableCount int
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id='workspace-primary' AND owner='identity' AND kind='identity.profile_binding' AND status='succeeded'`).Scan(&operationCount); err != nil || operationCount != 5 {
		t.Fatalf("shared profile binding operation count=%d err=%v", operationCount, err)
	}
	if err := identityStore.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_profile_binding_receipts'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy profile binding receipt table count=%d err=%v", legacyTableCount, err)
	}
}

func assertProfileBindingRole(t *testing.T, store *IdentityStore, userID, roleID, status, bindingKey, profileID string) {
	t.Helper()
	var actualStatus, actualBindingKey, actualProfileID string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT status, binding_key, profile_id FROM _identity_user_role_assignments WHERE workspace_id = 'workspace-primary' AND user_id = ? AND role_id = ?`, userID, roleID).
		Scan(&actualStatus, &actualBindingKey, &actualProfileID); err != nil {
		t.Fatal(err)
	}
	if actualStatus != status || actualBindingKey != bindingKey || actualProfileID != profileID {
		t.Fatalf("role user=%s role=%s status=%s binding=%s profile=%s", userID, roleID, actualStatus, actualBindingKey, actualProfileID)
	}
}

func identitySQLStoreForProfileBindingTest(t *testing.T, store *IdentityStore) *identitypersistence.SQLIdentityStore {
	t.Helper()
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	bindSharedOperations(t, identityStore)
	return identityStore
}

func profileBindingMutation(profileID string, operation identitymodel.IdentityProfileBindingOperation, userID string, expectedVersion int64, idempotencyKey string) identitymodel.IdentityProfileBindingMutation {
	return identitymodel.IdentityProfileBindingMutation{
		WorkspaceID: "workspace-primary", BindingKey: "member", ObjectKey: "member_profile", ProfileID: profileID, IdentityField: "identity_user",
		Operation: operation, IdentityUserID: userID, ExpectedVersion: expectedVersion, IdempotencyKey: idempotencyKey,
		RequestFingerprint: string(operation) + ":" + userID + ":" + idempotencyKey, ActorID: "actor",
	}
}

func assertProfileBindingRecordUser(t *testing.T, store *IdentityStore, profileID, expected string) {
	t.Helper()
	var actual string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COALESCE(identity_user, '') FROM member_profile WHERE workspace_id = 'workspace-primary' AND id = ?`, profileID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("profile %s identity=%q want=%q", profileID, actual, expected)
	}
}
