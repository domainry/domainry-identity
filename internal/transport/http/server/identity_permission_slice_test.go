package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

func TestStandalonePermissionAPIProjectsDatabaseStateAndActionBindingsWithRoleEnforcement(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-permission-slice.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	identityServer, err := httpserver.NewWithStore(t.Context(), cfg, store, httpserver.ServerAssemblyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	testServer := httptest.NewServer(identityServer.Routes())
	t.Cleanup(testServer.Close)

	adminToken := loginAccessToken(t, testServer)
	allowed := permissionCatalogRequest(t, testServer, adminToken)
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("admin permission catalog status=%d body=%s", allowed.StatusCode, readResponseBody(t, allowed))
	}
	var permissions []identitymodel.IdentityPermissionDefinition
	if err := json.NewDecoder(allowed.Body).Decode(&permissions); err != nil {
		t.Fatal(err)
	}
	_ = allowed.Body.Close()
	if len(permissions) != 4 {
		t.Fatalf("permission count=%d values=%+v", len(permissions), permissions)
	}
	for _, permission := range permissions {
		if permission.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive || !permission.Enabled || permission.SourceOwner != "identity:builtin" || len(permission.ActionUsages) == 0 {
			t.Fatalf("permission projection=%+v", permission)
		}
		for _, usage := range permission.ActionUsages {
			if usage.HTTPMethod == "" || usage.RouteTemplate == "" || usage.CapabilityKey == "" || usage.OperationKey == "" {
				t.Fatalf("incomplete live action usage=%+v", usage)
			}
		}
	}

	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RemoveIdentityUserRole(t.Context(), "workspace-primary", "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := repository.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{UserID: "admin", RoleID: "system_administrator"}); err != nil {
		t.Fatal(err)
	}
	limitedToken := loginAccessToken(t, testServer)
	denied := permissionCatalogRequest(t, testServer, limitedToken)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("system administrator without identity.permissions.read status=%d body=%s", denied.StatusCode, readResponseBody(t, denied))
	}
}

func TestStandaloneRolePermissionPublicationVersionsRoleSchemaAndSurvivesRestart(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-role-permission-publication.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	openServer := func() (*database.IdentityStore, *httpserver.Server, *httptest.Server) {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		identityServer, err := httpserver.NewWithStore(t.Context(), cfg, store, httpserver.ServerAssemblyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return store, identityServer, httptest.NewServer(identityServer.Routes())
	}

	store, identityServer, testServer := openServer()
	adminToken := loginAccessToken(t, testServer)
	initial, initialHash, initialVersion := rolePermissionConfiguration(t, testServer, adminToken, "organization_administrator")
	initialKeys := rolePermissionKeys(initial)
	if !slices.Contains(initialKeys, "identity.permissions.read") || !slices.Contains(initialKeys, "identity.permissions.write") {
		t.Fatalf("organization administrator is missing the S0 permissions: %v", initialKeys)
	}
	beforeRole := storedRoleSchema(t, store, "organization_administrator")

	requestedKeys := slices.DeleteFunc(slices.Clone(initialKeys), func(key string) bool {
		return key == "identity.permissions.read"
	})
	published, publishedHash, publishedVersion := publishRolePermissions(t, testServer, adminToken, "organization_administrator", initialHash, "role-permission-publication-1", requestedKeys, "verify direct RoleSchema publication")
	if publishedHash == "" || publishedHash == initialHash || publishedVersion == "" || publishedVersion == initialVersion {
		t.Fatalf("publication revision did not advance: initial=%s/%s published=%s/%s", initialVersion, initialHash, publishedVersion, publishedHash)
	}
	if slices.Contains(rolePermissionKeys(published), "identity.permissions.read") {
		t.Fatalf("published role still grants identity.permissions.read: %+v", published)
	}
	afterRole := storedRoleSchema(t, store, "organization_administrator")
	beforeRole.Permissions, afterRole.Permissions = nil, nil
	if !reflect.DeepEqual(beforeRole, afterRole) {
		t.Fatalf("permission publication changed non-permission RoleSchema fields:\nbefore=%+v\nafter=%+v", beforeRole, afterRole)
	}

	replayed, replayedHash, replayedVersion := publishRolePermissions(t, testServer, adminToken, "organization_administrator", initialHash, "role-permission-publication-1", requestedKeys, "verify direct RoleSchema publication")
	if replayedHash != publishedHash || replayedVersion != publishedVersion || !reflect.DeepEqual(replayed, published) {
		t.Fatalf("idempotent replay changed the result: first=%s/%s %+v replay=%s/%s %+v", publishedVersion, publishedHash, published, replayedVersion, replayedHash, replayed)
	}
	assertRolePermissionPublicationRows(t, store, 2, 1)

	staleKeys := append(slices.Clone(requestedKeys), "identity.permissions.read")
	stale := publishRolePermissionsResponse(t, testServer, adminToken, "organization_administrator", initialHash, "role-permission-publication-stale", staleKeys, "verify stale CAS")
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale RoleSchema publication status=%d body=%s", stale.StatusCode, readResponseBody(t, stale))
	}
	_ = stale.Body.Close()
	unknownKeys := append(slices.Clone(requestedKeys), "identity.permission.unknown")
	unknown := publishRolePermissionsResponse(t, testServer, adminToken, "organization_administrator", publishedHash, "role-permission-publication-unknown", unknownKeys, "verify fail closed selection")
	if unknown.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown permission publication status=%d body=%s", unknown.StatusCode, readResponseBody(t, unknown))
	}
	_ = unknown.Body.Close()
	assertRolePermissionPublicationRows(t, store, 2, 1)

	testServer.Close()
	if err := identityServer.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	restartedStore, restartedIdentityServer, restartedTestServer := openServer()
	t.Cleanup(restartedTestServer.Close)
	t.Cleanup(func() { _ = restartedIdentityServer.CloseContext(t.Context()) })
	restartedAdminToken := loginAccessToken(t, restartedTestServer)
	restarted, restartedHash, restartedVersion := rolePermissionConfiguration(t, restartedTestServer, restartedAdminToken, "organization_administrator")
	if restartedHash != publishedHash || restartedVersion != publishedVersion || slices.Contains(rolePermissionKeys(restarted), "identity.permissions.read") {
		t.Fatalf("restarted RoleSchema differs from publication: version=%s hash=%s permissions=%v", restartedVersion, restartedHash, rolePermissionKeys(restarted))
	}
	assertRolePermissionPublicationRows(t, restartedStore, 2, 1)

	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), restartedStore.DB(), restartedStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RemoveIdentityUserRole(t.Context(), "workspace-primary", "admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := repository.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{UserID: "admin", RoleID: "organization_administrator"}); err != nil {
		t.Fatal(err)
	}
	limitedToken := loginAccessToken(t, restartedTestServer)
	denied := permissionCatalogRequest(t, restartedTestServer, limitedToken)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("published role without identity.permissions.read status=%d body=%s", denied.StatusCode, readResponseBody(t, denied))
	}
}

func loginAccessToken(t *testing.T, server *httptest.Server) string {
	t.Helper()
	response := browserRequest(t, server.Client(), http.MethodPost, server.URL+"/browser/auth/login", `{"workspace_id":"workspace-primary","login":"admin@example.com","password":"Domainry@2026"}`, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.StatusCode, readResponseBody(t, response))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if payload.AccessToken == "" {
		t.Fatal("login did not return an access token")
	}
	return payload.AccessToken
}

func permissionCatalogRequest(t *testing.T, server *httptest.Server, accessToken string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/identity/permissions", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func rolePermissionConfiguration(t *testing.T, server *httptest.Server, accessToken, roleID string) ([]identitymodel.IdentityRolePermissionAssignment, string, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/identity/roles/"+roleID+"/permissions", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("role permission configuration status=%d body=%s", response.StatusCode, readResponseBody(t, response))
	}
	defer response.Body.Close()
	assignments := []identitymodel.IdentityRolePermissionAssignment{}
	if err := json.NewDecoder(response.Body).Decode(&assignments); err != nil {
		t.Fatal(err)
	}
	hash, version := response.Header.Get("X-Resource-Hash"), response.Header.Get("X-Schema-Version")
	if hash == "" || version == "" {
		t.Fatalf("role permission configuration omitted revision headers: hash=%q version=%q", hash, version)
	}
	return assignments, hash, version
}

func publishRolePermissions(t *testing.T, server *httptest.Server, accessToken, roleID, expectedHash, operationID string, permissionKeys []string, reason string) ([]identitymodel.IdentityRolePermissionAssignment, string, string) {
	t.Helper()
	response := publishRolePermissionsResponse(t, server, accessToken, roleID, expectedHash, operationID, permissionKeys, reason)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("role permission publication status=%d body=%s", response.StatusCode, readResponseBody(t, response))
	}
	defer response.Body.Close()
	assignments := []identitymodel.IdentityRolePermissionAssignment{}
	if err := json.NewDecoder(response.Body).Decode(&assignments); err != nil {
		t.Fatal(err)
	}
	return assignments, response.Header.Get("X-Resource-Hash"), response.Header.Get("X-Schema-Version")
}

func publishRolePermissionsResponse(t *testing.T, server *httptest.Server, accessToken, roleID, expectedHash, operationID string, permissionKeys []string, reason string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(identitymodel.IdentityRolePermissionPublicationRequest{PermissionKeys: permissionKeys, BusinessReason: reason})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/identity/roles/"+roleID+"/permissions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	request.Header.Set("Expected-Schema-Hash", expectedHash)
	request.Header.Set("Idempotency-Key", operationID)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func rolePermissionKeys(assignments []identitymodel.IdentityRolePermissionAssignment) []string {
	keys := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		keys = append(keys, assignment.PermissionKey)
	}
	slices.Sort(keys)
	return keys
}

func storedRoleSchema(t *testing.T, store *database.IdentityStore, roleKey string) identitymodel.RoleSchema {
	t.Helper()
	var payload []byte
	if err := store.DB().QueryRowContext(t.Context(), `SELECT payload_json FROM _identity_role_definitions WHERE resource_key = ?`, roleKey).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var role identitymodel.RoleSchema
	if err := json.Unmarshal(payload, &role); err != nil {
		t.Fatal(err)
	}
	return role
}

func assertRolePermissionPublicationRows(t *testing.T, store *database.IdentityStore, wantVersions, wantAudits int) {
	t.Helper()
	var versions int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_role_definition_versions WHERE resource_type = ? AND resource_key = ?`, "role", "organization_administrator").Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != wantVersions {
		t.Fatalf("role definition version rows=%d want=%d", versions, wantVersions)
	}
	var audits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND object_key = ? AND record_id = ?`, "workspace-primary", "identity_role_permissions.published", "role", "organization_administrator").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != wantAudits {
		t.Fatalf("role permission publication audit rows=%d want=%d", audits, wantAudits)
	}
}
