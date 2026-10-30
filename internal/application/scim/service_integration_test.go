package scim

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	scimpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/scim"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type testSessionRevoker struct{}

func (testSessionRevoker) ForceLogoutUser(context.Context, string, string) (int, error) {
	return 0, nil
}

func TestSCIMUserAndGroupLifecycleUsesIdentityAndDirectoryFacts(t *testing.T) {
	service, identityStore, repository, databaseStore := openSCIMService(t)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	active := true
	created, err := service.CreateUser(ctx, scimmodel.User{
		Schemas: []string{scimmodel.SchemaUser, scimmodel.SchemaEnterpriseUser}, UserName: "ada@example.com", DisplayName: "Ada Lovelace", Active: &active,
		Name: scimmodel.Name{GivenName: "Ada", FamilyName: "Lovelace"}, Emails: []scimmodel.MultiValue{{Value: "ada@example.com", Type: "work", Primary: true}},
		EnterpriseUser: &scimmodel.EnterpriseUser{EmployeeNumber: "E-1", Department: "untrusted-directory-org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Meta.Version == "" || created.Meta.Location != "/scim/v2/Users/"+created.ID || created.EnterpriseUser == nil || created.EnterpriseUser.Department != "untrusted-directory-org" {
		t.Fatalf("created user=%+v", created)
	}
	identityUser, found, err := identityStore.GetIdentityUser(ctx, "workspace-a", created.ID)
	if err != nil || !found || identityUser.WorkerNo != "E-1" || identityUser.OrgID != "" {
		t.Fatalf("identity user=%+v found=%v err=%v", identityUser, found, err)
	}

	group, err := service.CreateGroup(ctx, scimmodel.Group{Schemas: []string{scimmodel.SchemaGroup}, DisplayName: "Engineering", Members: []scimmodel.Member{{Value: created.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Members) != 1 || group.Members[0].Value != created.ID {
		t.Fatalf("created group=%+v", group)
	}

	patched, err := service.PatchUser(ctx, created.ID, scimmodel.PatchRequest{
		Schemas: []string{scimmodel.SchemaPatch}, Operations: []scimmodel.PatchOperation{{Op: "replace", Path: "active", Value: false}},
	}, created.Meta.Version)
	if err != nil {
		t.Fatal(err)
	}
	if patched.Active == nil || *patched.Active || patched.Meta.Version == created.Meta.Version {
		t.Fatalf("patched user=%+v", patched)
	}
	identityUser, found, err = identityStore.GetIdentityUser(ctx, "workspace-a", created.ID)
	if err != nil || !found || identityUser.Status != identitymodel.IdentityStatusDisabled {
		t.Fatalf("disabled identity user=%+v found=%v err=%v", identityUser, found, err)
	}

	if err := service.DeleteUser(ctx, created.ID, patched.Meta.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetUser(ctx, created.ID); err == nil {
		t.Fatal("deleted SCIM resource remains readable")
	}
	directoryGroup, found, err := repository.GetGroup(ctx, "workspace-a", group.ID)
	if err != nil || !found || directoryGroup.Version != 2 || len(directoryGroup.MemberIDs) != 0 {
		t.Fatalf("directory group after user delete=%+v found=%v err=%v", directoryGroup, found, err)
	}
	var refreshTokens int
	if err := databaseStore.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM _identity_auth_refresh_tokens WHERE workspace_id=? AND user_id=? AND revoked_at=0`, "workspace-a", created.ID).Scan(&refreshTokens); err != nil || refreshTokens != 0 {
		t.Fatalf("active refresh tokens=%d err=%v", refreshTokens, err)
	}
	restored, err := service.CreateUser(ctx, scimmodel.User{Schemas: []string{scimmodel.SchemaUser}, UserName: "ADA@EXAMPLE.COM", Active: &active, Emails: []scimmodel.MultiValue{{Value: "ada@example.com", Primary: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != created.ID || restored.Active == nil || !*restored.Active {
		t.Fatalf("restored user=%+v original=%+v", restored, created)
	}
}

func TestSCIMCreateRollsBackIdentityWhenDirectoryWriteFails(t *testing.T) {
	service, identityStore, _, databaseStore := openSCIMService(t)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-a")
	if _, err := databaseStore.DB().ExecContext(ctx, `CREATE TRIGGER fail_scim_user_create BEFORE INSERT ON _identity_scim_users BEGIN SELECT RAISE(ABORT,'injected SCIM failure'); END`); err != nil {
		t.Fatal(err)
	}
	active := true
	_, err := service.CreateUser(ctx, scimmodel.User{Schemas: []string{scimmodel.SchemaUser}, UserName: "rollback@example.com", Active: &active, Emails: []scimmodel.MultiValue{{Value: "rollback@example.com", Primary: true}}})
	var scimErr *Error
	if err == nil || errors.As(err, &scimErr) {
		t.Fatalf("create error=%v", err)
	}
	users, err := identityStore.ListIdentityUsers(ctx, "workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Fatalf("failed SCIM create left Identity users=%+v", users)
	}
}

func openSCIMService(t *testing.T) (*Service, *identitypersistence.SQLIdentityStore, *scimpersistence.Store, *database.IdentityStore) {
	t.Helper()
	databaseStore, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "scim-service.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Close() })
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	repository := scimpersistence.NewStore(identityStore)
	service, err := NewService(identityapplication.NewIdentityApplicationService(identityStore, nil), testSessionRevoker{}, repository, identityStore)
	if err != nil {
		t.Fatal(err)
	}
	return service, identityStore, repository, databaseStore
}
