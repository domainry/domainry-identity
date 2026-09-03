package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestAuthRoutesBindMethodsAndPaths(t *testing.T) {
	handler := NewAuthHandler(AuthDependencies{})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/auth/login", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method route status=%d", response.Code)
	}
}

func TestAuthProviderSetupRequiresItsExactDatabaseBackedActionPermission(t *testing.T) {
	authorizer := newAuthRouteTestAuthorizer(t)
	for _, test := range []struct {
		name       string
		permission string
		want       int
	}{
		{name: "another exact Permission is not an alias", permission: "identity.roles.list", want: http.StatusForbidden},
		{name: "exact Action permission", permission: "auth.providers.setup", want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewAuthHandler(AuthDependencies{
				ActionAuthorization: authorizer,
				Principal: func(*http.Request) identitymodel.Principal {
					return identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, test.permission)}}
				},
				WriteError: func(w http.ResponseWriter, _ *http.Request, status int, _ string, _ ...string) { w.WriteHeader(status) },
				DecodeJSON: func(w http.ResponseWriter, _ *http.Request, _ any) bool {
					w.WriteHeader(http.StatusNoContent)
					return false
				},
			})
			mux := http.NewServeMux()
			handler.RegisterRoutes(mux)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/auth/providers/oidc/setup", nil))
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d", response.Code, test.want)
			}
		})
	}
}

type authRoutePermissionRepository struct {
	records []identitymodel.IdentityPermissionDefinitionRecord
}

func (repository *authRoutePermissionRepository) ListIdentityPermissionDefinitions(context.Context, string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	return slices.Clone(repository.records), nil
}

func (*authRoutePermissionRepository) GetIdentityPermissionDefinition(context.Context, string, string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error) {
	return identitymodel.IdentityPermissionDefinitionRecord{}, false, nil
}

func (*authRoutePermissionRepository) SetIdentityPermissionDefinitionEnabled(context.Context, string, string, bool) (bool, error) {
	return false, nil
}

func (repository *authRoutePermissionRepository) ReconcileIdentityPermissionDefinitions(_ context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	repository.records = slices.Clone(request.Definitions)
	return identitymodel.IdentityPermissionReconcileReceipt{WorkspaceID: request.WorkspaceID, SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash}, nil
}

func newAuthRouteTestAuthorizer(t *testing.T) *identityapplication.IdentityActionAuthorizationService {
	t.Helper()
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := identityapplication.NewIdentityPermissionCatalogApplicationService(&authRoutePermissionRepository{}, registry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner); err != nil {
		t.Fatal(err)
	}
	return identityapplication.NewIdentityActionAuthorizationService(registry, catalog)
}
