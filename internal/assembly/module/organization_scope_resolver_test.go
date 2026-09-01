package moduleassembly

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type testEmbeddedMigrationRegistrar struct{}

func (testEmbeddedMigrationRegistrar) ApplyOwnedMigration(ctx context.Context, _ string, _ uint, _, _ string, apply func(context.Context) error) error {
	return apply(ctx)
}

func TestModuleOrganizationScopeResolverAdaptsSDKContract(t *testing.T) {
	wantErr := errors.New("scope unavailable")
	profiles := []string{"workforce-2", "workforce-1"}
	resolver := moduleOrganizationScopeResolver{resolve: func(_ context.Context, workspaceID string, gotProfiles []string) (identitysdk.OrganizationScopes, error) {
		if workspaceID != "workspace-1" || !reflect.DeepEqual(gotProfiles, profiles) {
			t.Fatalf("workspace=%q profiles=%#v", workspaceID, gotProfiles)
		}
		gotProfiles[0] = "mutated"
		return identitysdk.OrganizationScopes{TeamIDs: []string{"team-1"}, StoreIDs: []string{"store-1"}, TerritoryIDs: []string{"territory-1"}, WarehouseIDs: []string{"warehouse-1"}}, nil
	}}
	facts, err := resolver.ResolveIdentityOrganizationScopes(t.Context(), "workspace-1", profiles)
	if err != nil || profiles[0] != "workforce-2" || !reflect.DeepEqual(facts.TeamIDs, []string{"team-1"}) || !reflect.DeepEqual(facts.StoreIDs, []string{"store-1"}) || !reflect.DeepEqual(facts.TerritoryIDs, []string{"territory-1"}) || !reflect.DeepEqual(facts.WarehouseIDs, []string{"warehouse-1"}) {
		t.Fatalf("facts=%#v profiles=%#v err=%v", facts, profiles, err)
	}

	resolver.resolve = func(context.Context, string, []string) (identitysdk.OrganizationScopes, error) {
		return identitysdk.OrganizationScopes{}, wantErr
	}
	if _, err := resolver.ResolveIdentityOrganizationScopes(t.Context(), "workspace-1", profiles); !errors.Is(err, wantErr) {
		t.Fatalf("resolver error=%v", err)
	}
}

func TestFactoryWiresBorrowedOrganizationScopeResolverIntoPrincipalBuild(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "project.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	called := false
	factory := NewFactory(Options{DatabaseDriver: "sqlite", DatabasePath: dbPath})
	binding, err := factory.OpenWithDatabase(t.Context(), identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"}, identitysdk.DatabaseHandle{
		Pool: db, Driver: "sqlite", FilePath: dbPath, Migrations: testEmbeddedMigrationRegistrar{},
		OrganizationScopeResolver: func(_ context.Context, workspaceID string, profileIDs []string) (identitysdk.OrganizationScopes, error) {
			called = workspaceID == "workspace-primary" && reflect.DeepEqual(profileIDs, []string{"workforce-admin"})
			return identitysdk.OrganizationScopes{StoreIDs: []string{"store-1"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	module, ok := binding.(*moduleBinding)
	if !ok {
		t.Fatalf("binding type=%T", binding)
	}
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	if err := module.runtime.Identity.UpsertWorkforceProfile(ctx, identitymodel.IdentityWorkforceProfile{
		ID: "workforce-admin", OrganizationID: "organization", IdentityUserID: "admin", WorkerNo: "A-1",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}); err != nil {
		t.Fatal(err)
	}
	principal, err := module.runtime.Identity.ResolvePrincipal(ctx, "admin")
	if err != nil || !called || !reflect.DeepEqual(principal.StoreIDs, []string{"store-1"}) {
		t.Fatalf("principal=%#v called=%v err=%v", principal, called, err)
	}
}
