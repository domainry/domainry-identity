package identity_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type profileClaimSQLRecordReader struct {
	db *sql.DB
}

func (r profileClaimSQLRecordReader) GetIdentityProfileBindingRecord(ctx context.Context, workspaceID string, _ definitionmodel.ObjectSchema, profileID string) (map[string]any, bool, error) {
	var identityUser sql.NullString
	var email string
	err := r.db.QueryRowContext(ctx, `SELECT identity_user, email FROM member_profile WHERE workspace_id = ? AND id = ?`, workspaceID, profileID).Scan(&identityUser, &email)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return map[string]any{"identity_user": identityUser.String, "email": email}, true, nil
}

func TestUnboundProfileCanBeClaimedAfterAccountRegistrationWithoutTrustingClientUserID(t *testing.T) {
	databaseStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "profile-claim.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Close() })
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().ExecContext(t.Context(), `CREATE TABLE member_profile (
		workspace_id TEXT NOT NULL, id TEXT PRIMARY KEY, identity_user TEXT, email TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseStore.DB().ExecContext(t.Context(), `INSERT INTO member_profile VALUES ('workspace-primary', 'member-1', NULL, 'member@example.com', 'now', 'now')`); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	bindTestAuditModule(t, databaseStore, identityStore)
	bindSharedOperations(t, identityStore)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	for _, user := range []identitymodel.IdentityUser{
		{ID: "registered-user", Email: "member@example.com", Status: identitymodel.IdentityStatusActive},
		{ID: "competing-user", Email: "competitor@example.com", Status: identitymodel.IdentityStatusActive},
	} {
		if err := identityStore.UpsertIdentityUser(ctx, "workspace-primary", user); err != nil {
			t.Fatal(err)
		}
	}
	identity := identityapplication.NewIdentityApplicationService(identityStore, nil)
	object := definitionmodel.ObjectSchema{Key: "member_profile"}
	extension := identitymodel.IdentityProfileExtension{
		ObjectKey: "member_profile", IdentityRelationField: "identity_user",
		BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "member"},
		BindingLifecycle: identitymodel.IdentityProfileBindingLifecycle{
			AllowUnbound: true, ClaimProofs: []identitymodel.IdentityProfileClaimProof{{Type: "email", FieldKey: "email"}},
		},
	}
	service := identityapplication.NewIdentityProfileBindingApplicationService(identityapplication.IdentityProfileBindingDependencies{
		Repository: identitypersistence.NewIdentityProfileBindingStore(identityStore),
		Records:    profileClaimSQLRecordReader{db: databaseStore.DB()}, Identity: identity,
		Objects: func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{object} },
		Extensions: func() []identitymodel.IdentityProfileExtension {
			return []identitymodel.IdentityProfileExtension{extension}
		},
	})
	request := identityapplication.IdentityProfileBindingCommandRequest{
		ObjectKey: "member_profile", ProfileID: "member-1", BindingKey: "member", Operation: "claim",
		IdentityUserID: "attacker-controlled", ClaimProofType: "email", ClaimProofValue: "member@example.com",
		ExpectedVersion: 0, IdempotencyKey: "claim-1",
	}
	principal := identitymodel.Principal{Known: true, UserID: "registered-user", WorkspaceID: "workspace-primary"}
	receipt, err := service.Execute(ctx, request, principal)
	if err != nil || receipt.Binding.IdentityUserID != "registered-user" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	replay, err := service.Execute(ctx, request, principal)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	request.ExpectedVersion, request.IdempotencyKey = 1, "claim-2"
	if _, err := service.Execute(ctx, request, identitymodel.Principal{Known: true, UserID: "competing-user", WorkspaceID: "workspace-primary"}); apperror.CodeOf(err) != "backend.identity.profile_already_bound" {
		t.Fatalf("competing claim error=%v", err)
	}
}
