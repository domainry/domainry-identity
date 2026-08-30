package identity_test

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityDirectoriesPageAndSearchInSQLAtOneHundredThousandRows(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-scale.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `WITH RECURSIVE n(i) AS (
		SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000
	) INSERT INTO _identity_users (id, workspace_id, name, email, phone, status, created_at, updated_at)
	SELECT printf('user-%06d', i), 'default', printf('User %06d', i), printf('user-%06d@example.test', i), '', 'active', 'now', 'now' FROM n`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.DB().ExecContext(t.Context(), `WITH RECURSIVE n(i) AS (
		SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000
	) INSERT INTO _identity_workforce_profiles
	(id, workspace_id, organization_id, identity_user_id, worker_no, worker_type, work_status, start_date, end_date, primary_assignment_id, version, created_at, updated_at)
	SELECT printf('workforce-%06d', i), 'default', 'org-1', printf('user-%06d', i), printf('E-%06d', i), 'employee', 'active', NULL, NULL, NULL, 1, 'now', 'now' FROM n`); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	service := identityapplication.NewIdentityApplicationService(repository, nil)
	ctx := requestcontext.WithWorkspaceID(t.Context(), "default")
	users, err := service.SearchUsers(ctx, identitymodel.IdentityListQuery{
		AfterID: "user-099980", PageSize: 20, Sort: []identitymodel.IdentitySortRule{{Field: "id", Direction: "asc"}},
	})
	if err != nil || users.Total != 100000 || len(users.Items) != 20 || users.Items[0].ID != "user-099981" || users.HasNext {
		t.Fatalf("users page=%+v err=%v", users, err)
	}
	users, err = service.SearchUsers(ctx, identitymodel.IdentityListQuery{Search: "user-100000@example.test", PageSize: 20})
	if err != nil || users.Total != 1 || len(users.Items) != 1 || users.Items[0].ID != "user-100000" {
		t.Fatalf("users search=%+v err=%v", users, err)
	}
	workforce, err := service.SearchWorkforceProfiles(ctx, identitymodel.IdentityListQuery{
		Search: "E-100000", SearchFields: []string{"worker_no"}, PageSize: 20,
	})
	if err != nil || workforce.Total != 1 || len(workforce.Items) != 1 || workforce.Items[0].ID != "workforce-100000" {
		t.Fatalf("workforce search=%+v err=%v", workforce, err)
	}
	facts, err := repository.ListIdentityUserDirectoryFacts(ctx, "default", []string{"user-000001", "user-100000"})
	if err != nil || len(facts.WorkforceProfiles) != 2 {
		t.Fatalf("bounded directory facts=%+v err=%v", facts, err)
	}
	securityFacts, err := authpersistence.NewAuthStore(repository).ListUserDirectorySecurityFacts(ctx, "default", []string{"user-000001", "user-100000"})
	if err != nil || len(securityFacts) != 2 {
		t.Fatalf("bounded security facts=%+v err=%v", securityFacts, err)
	}
}
