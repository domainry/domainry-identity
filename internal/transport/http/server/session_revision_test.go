package httpserver_test

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityprincipal "github.com/domainry/domainry-identity-sdk/authorization/principal"
	identityremote "github.com/domainry/domainry-identity-sdk/remote"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

func TestSessionRevisionThroughEmbeddedAndRemoteBindings(t *testing.T) {
	for _, mode := range []string{"embedded", "remote"} {
		t.Run(mode, func(t *testing.T) {
			_, sourceFile, _, _ := runtime.Caller(0)
			server := httptest.NewUnstartedServer(nil)
			cfg := config.FromEnv()
			cfg.Environment, cfg.DatabaseDriver = "development", "sqlite"
			cfg.DBPath = filepath.Join(t.TempDir(), "revision.db")
			cfg.ManifestPath = filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "..", "domainry.template.json")
			cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "revision-runtime"
			cfg.AuthIssuer = "http://" + server.Listener.Addr().String()
			cfg.IdentityApplicationServiceCredentials = map[string]string{"workspace-primary/revision-runtime": "revision-service-test-credential"}
			store, err := database.OpenContext(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := httpserver.NewWithStore(t.Context(), cfg, store, testServerAssemblyOptions())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.CloseContext(t.Context()) })
			server.Config.Handler = owner.Routes()
			server.Start()
			t.Cleanup(server.Close)
			binding := owner.SDKBinding()
			if mode == "remote" {
				factory := identityremote.NewFactory(identityremote.Config{Endpoint: server.URL, WorkspaceID: cfg.IdentityWorkspaceID, Issuer: cfg.AuthIssuer, Audience: cfg.AuthAudience, ServiceAccessToken: "revision-service-test-credential", HTTPClient: server.Client()})
				binding, err = factory.Open(t.Context(), identitysdk.ApplicationRef{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = binding.Close(t.Context()) })
			}
			application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "revision-runtime"}
			if _, err := binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
				t.Fatal(err)
			}
			login, err := binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: "Domainry@2026"})
			if err != nil {
				t.Fatal(err)
			}
			resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{})
			if err != nil {
				t.Fatal(err)
			}
			before, err := resolver.Authenticate(t.Context(), login.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			repo, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.UpsertIdentityOrganizationUnit(t.Context(), cfg.IdentityWorkspaceID, identitymodel.IdentityOrganizationUnit{ID: "moved-department", Code: "moved", Name: "Moved department", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Status: identitymodel.IdentityStatusActive}); err != nil {
				t.Fatal(err)
			}
			user, found, err := repo.GetIdentityUser(t.Context(), cfg.IdentityWorkspaceID, before.UserID)
			if err != nil || !found {
				t.Fatalf("source user missing: found=%v err=%v", found, err)
			}
			user.OrgID = "moved-department"
			if err := repo.UpsertIdentityUser(t.Context(), cfg.IdentityWorkspaceID, user); err != nil {
				t.Fatal(err)
			}
			current, err := binding.Authentication().CurrentSession(t.Context(), identitysdk.CurrentSessionRequest{AccessToken: login.AccessToken})
			if err != nil || current.AuthorizationRevision == "" || string(current.AuthorizationRevision) == before.AuthorizationRevision {
				t.Fatalf("current session echoed the old issuance revision: err=%v", err)
			}
			_, err = resolver.Authenticate(t.Context(), login.AccessToken)
			var coded *identitysdk.Error
			if !errors.As(err, &coded) || coded.Code != "identity.authorization_revision_stale" {
				t.Fatalf("cached old session was not rejected: %v", err)
			}
			refreshed, err := binding.Authentication().RefreshSession(t.Context(), identitysdk.RefreshRequest{WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, RefreshToken: login.RefreshToken})
			if err != nil {
				t.Fatal(err)
			}
			after, err := resolver.Authenticate(t.Context(), refreshed.AccessToken)
			if err != nil || after.OrgID != "moved-department" || after.AuthorizationRevision != string(current.AuthorizationRevision) {
				t.Fatalf("refreshed session did not use the current revision and department: err=%v", err)
			}
		})
	}
}
