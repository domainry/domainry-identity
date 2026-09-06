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
	"strings"
	"sync/atomic"
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
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
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	expectedPermissions := registry.OwnedPermissionDefinitions(identityapplication.IdentityBuiltinAuthorizationOwner)
	if len(expectedPermissions) != 95 || len(permissions) != 102 {
		t.Fatalf("database permission count=%d Identity owner registry count=%d", len(permissions), len(expectedPermissions))
	}
	ownerCounts := map[string]int{}
	for _, permission := range permissions {
		ownerCounts[permission.SourceOwner]++
		if permission.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive || !permission.Enabled || len(permission.ActionUsages) == 0 {
			t.Fatalf("permission projection=%+v", permission)
		}
		for _, usage := range permission.ActionUsages {
			if usage.ActionKey != permission.Key || usage.CapabilityKey == "" || usage.OperationKey == "" {
				t.Fatalf("incomplete live action usage=%+v", usage)
			}
			if permission.SourceOwner == identityapplication.IdentityBuiltinAuthorizationOwner {
				action, found := registry.Definition(usage.ActionKey)
				if !found || action.HTTP != nil && (usage.HTTPMethod == "" || usage.RouteTemplate == "") || action.HTTP == nil && (usage.HTTPMethod != "" || usage.RouteTemplate != "") {
					t.Fatalf("permission usage does not match registered Action: permission=%+v action=%+v", permission, action)
				}
			}
		}
	}
	if ownerCounts[identityapplication.IdentityBuiltinAuthorizationOwner] != 95 || ownerCounts["module:audit"] != 7 {
		t.Fatalf("permission owner counts=%v", ownerCounts)
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
		t.Fatalf("system administrator without identity.permissions.list status=%d body=%s", denied.StatusCode, readResponseBody(t, denied))
	}
}

func TestStandalonePermissionAPIQueriesRemoteRuntimeUsageWithoutPersistingIt(t *testing.T) {
	externalAction := inventoryModuleAction("module:inventory")
	runtimeRegistry := actioncontract.NewRegistry()
	if err := runtimeRegistry.Register(externalAction); err != nil {
		t.Fatal(err)
	}
	if err := runtimeRegistry.Freeze(); err != nil {
		t.Fatal(err)
	}
	var runtimeAvailable atomic.Bool
	runtimeAvailable.Store(true)
	var runtimeCalls atomic.Int64
	var forwardedAuthorization, forwardedWorkspace, forwardedRequestID atomic.Value
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		runtimeCalls.Add(1)
		forwardedAuthorization.Store(request.Header.Get("Authorization"))
		forwardedWorkspace.Store(request.Header.Get("X-Workspace-ID"))
		forwardedRequestID.Store(request.Header.Get("X-Request-ID"))
		if request.Method != http.MethodPost || request.URL.Path != "/action/permission-usages/query" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if !runtimeAvailable.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var query actioncontract.PermissionUsageRequest
		if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		snapshot, err := runtimeRegistry.QueryPermissionUsages(request.Context(), query)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(snapshot)
	}))
	defer runtimeServer.Close()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-remote-action-usage.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	cfg.IdentityActionUsageRuntimeURL = runtimeServer.URL
	runtimeVerifierCredential := "runtime-verifier-credential-for-action-usage"
	cfg.IdentityApplicationServiceCredentials = map[string]string{
		"workspace-primary/domainry-runtime":                                      runtimeVerifierCredential,
		"workspace-primary/domainry-identity-control-plane#identity-action-usage": "identity-action-usage-source-credential",
	}

	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	identityServer, err := httpserver.NewWithStore(t.Context(), cfg, store, httpserver.ServerAssemblyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	application := identitysdk.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "domainry-runtime"}
	if _, err := identityServer.SDKBinding().Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	reconcile, err := identitysdk.NewPermissionReconcileRequest(application, externalAction.Permission.Owner, "", []identitysdk.PermissionDefinition{{
		PermissionKey: externalAction.Permission.Key, ResourceKey: externalAction.Permission.ResourceKey,
		OperationKey: externalAction.Permission.OperationKey, Label: externalAction.Permission.Label,
		Category: externalAction.Permission.Category, SourceKind: externalAction.SourceKind,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityServer.SDKBinding().Permissions().Reconcile(t.Context(), reconcile); err != nil {
		t.Fatal(err)
	}

	identityHTTP := httptest.NewServer(identityServer.Routes())
	defer identityHTTP.Close()
	adminToken := loginAccessToken(t, identityHTTP)
	response := permissionCatalogRequest(t, identityHTTP, adminToken)
	permissions := decodePermissionDefinitions(t, response)
	external := permissionDefinitionByKey(t, permissions, externalAction.Key)
	if external.ActionUsageStatus != identitymodel.IdentityActionUsageAvailable || len(external.ActionUsages) != 1 || external.ActionUsages[0].RouteTemplate != externalAction.HTTP.RouteTemplate {
		t.Fatalf("remote Action usage=%+v", external)
	}
	forwardedBearer, _ := strings.CutPrefix(forwardedAuthorization.Load().(string), "Bearer ")
	if runtimeCalls.Load() != 1 || strings.TrimSpace(forwardedBearer) == "" || forwardedBearer == adminToken || forwardedWorkspace.Load() != "workspace-primary" || strings.TrimSpace(forwardedRequestID.Load().(string)) == "" {
		t.Fatalf("Runtime calls=%d authorization=%v workspace=%v request_id=%v", runtimeCalls.Load(), forwardedAuthorization.Load(), forwardedWorkspace.Load(), forwardedRequestID.Load())
	}
	serviceBinding, ok := identityServer.SDKBinding().(identitysdk.ApplicationServiceVerificationBinding)
	if !ok || serviceBinding.ApplicationServiceVerifier() == nil {
		t.Fatal("Identity SDK binding does not expose service token verification")
	}
	servicePrincipal, err := serviceBinding.ApplicationServiceVerifier().Verify(t.Context(), identitysdk.VerifyApplicationServiceTokenRequest{
		AccessToken: forwardedBearer, Audience: "domainry-runtime",
		Grant: identitysdk.ApplicationServiceGrant{Resource: "runtime.action.permission_usages", Action: "query"},
	})
	if err != nil || servicePrincipal.Application.ApplicationKey != "domainry-identity-control-plane" || servicePrincipal.Audience != "domainry-runtime" || servicePrincipal.CredentialID != "identity-action-usage" {
		t.Fatalf("Runtime service principal=%+v err=%v", servicePrincipal, err)
	}
	verifyBody, err := json.Marshal(identitysdk.VerifyApplicationServiceTokenRequest{
		AccessToken: forwardedBearer, Audience: "domainry-runtime",
		Grant: identitysdk.ApplicationServiceGrant{Resource: "runtime.action.permission_usages", Action: "query"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, identityHTTP.URL+"/identity/application-service/verify", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest.Header.Set("Authorization", "Bearer "+runtimeVerifierCredential)
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyRequest.Header.Set("X-Domainry-Tenant-ID", "workspace-primary")
	verifyRequest.Header.Set("X-Domainry-Workspace-ID", "workspace-primary")
	verifyResponse, err := identityHTTP.Client().Do(verifyRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyResponse.Body.Close()
	var remotelyVerified identitysdk.ApplicationServicePrincipal
	if verifyResponse.StatusCode != http.StatusOK || json.NewDecoder(verifyResponse.Body).Decode(&remotelyVerified) != nil || remotelyVerified.CredentialID != "identity-action-usage" {
		t.Fatalf("remote service-token verification status=%d principal=%+v", verifyResponse.StatusCode, remotelyVerified)
	}

	runtimeAvailable.Store(false)
	unavailableResponse := permissionCatalogRequest(t, identityHTTP, adminToken)
	unavailable := permissionDefinitionByKey(t, decodePermissionDefinitions(t, unavailableResponse), externalAction.Key)
	if unavailable.ActionUsageStatus != identitymodel.IdentityActionUsageUnavailable || len(unavailable.ActionUsages) != 0 {
		t.Fatalf("unreachable owner reused persisted usage=%+v", unavailable)
	}
	if runtimeCalls.Load() != 2 {
		t.Fatalf("Runtime query calls=%d want=2", runtimeCalls.Load())
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
	if !slices.Contains(initialKeys, "identity.role_permissions.list") || !slices.Contains(initialKeys, "identity.role_permissions.publish") {
		t.Fatalf("organization administrator is missing exact role-permission Actions: %v", initialKeys)
	}
	beforeRole := storedRoleSchema(t, store, "organization_administrator")

	requestedKeys := slices.DeleteFunc(slices.Clone(initialKeys), func(key string) bool {
		return key == "identity.role_permissions.list"
	})
	published, publishedHash, publishedVersion := publishRolePermissions(t, testServer, adminToken, "organization_administrator", initialHash, "role-permission-publication-1", requestedKeys, "verify direct RoleSchema publication")
	if publishedHash == "" || publishedHash == initialHash || publishedVersion == "" || publishedVersion == initialVersion {
		t.Fatalf("publication revision did not advance: initial=%s/%s published=%s/%s", initialVersion, initialHash, publishedVersion, publishedHash)
	}
	if slices.Contains(rolePermissionKeys(published), "identity.role_permissions.list") {
		t.Fatalf("published role still grants identity.role_permissions.list: %+v", published)
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

	staleKeys := append(slices.Clone(requestedKeys), "identity.role_permissions.list")
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
	if restartedHash != publishedHash || restartedVersion != publishedVersion || slices.Contains(rolePermissionKeys(restarted), "identity.role_permissions.list") {
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
	limitedPublishKeys := slices.DeleteFunc(slices.Clone(requestedKeys), func(key string) bool {
		return key == "identity.role_permissions.validate"
	})
	limitedPublished, limitedPublishedHash, limitedPublishedVersion := publishRolePermissions(t, restartedTestServer, limitedToken, "organization_administrator", restartedHash, "role-permission-publication-without-list", limitedPublishKeys, "prove publish does not acquire list permission")
	if limitedPublishedHash == restartedHash || limitedPublishedVersion == restartedVersion || slices.Contains(rolePermissionKeys(limitedPublished), "identity.role_permissions.validate") {
		t.Fatalf("exact publish without list did not advance RoleSchema: version=%s hash=%s permissions=%v", limitedPublishedVersion, limitedPublishedHash, rolePermissionKeys(limitedPublished))
	}
	denied := rolePermissionConfigurationResponse(t, restartedTestServer, limitedToken, "organization_administrator")
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("published role without identity.role_permissions.list status=%d body=%s", denied.StatusCode, readResponseBody(t, denied))
	}
	_ = denied.Body.Close()
	stillAllowed := permissionCatalogRequest(t, restartedTestServer, limitedToken)
	if stillAllowed.StatusCode != http.StatusOK {
		t.Fatalf("removing identity.role_permissions.list affected identity.permissions.list status=%d body=%s", stillAllowed.StatusCode, readResponseBody(t, stillAllowed))
	}
	_ = stillAllowed.Body.Close()
}

func TestStandaloneRoleAndPolicyAuthoringPublishesRoleSchemaDirectly(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity-role-policy-publication.db")
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

	create := identitymodel.IdentityRoleDefinitionMutationRequest{
		Role: identitymodel.RoleSchema{
			Key: "auditor", Name: "Auditor", Description: "Reads audit resources",
			Permissions:      identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list"),
			FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "invoice", FieldKey: "amount", Read: true, Write: true}},
		},
		BusinessReason: "create a least-privilege audit role",
	}
	created := identityRolePolicyRequest(t, testServer, adminToken, http.MethodPost, "/identity/roles", "", "role-create-1", create)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("role create status=%d body=%s", created.StatusCode, readResponseBody(t, created))
	}
	createdHash, createdVersion := created.Header.Get("X-Resource-Hash"), created.Header.Get("X-Schema-Version")
	_ = created.Body.Close()
	if createdHash == "" || createdVersion != "1" {
		t.Fatalf("created role revision=%s/%s", createdVersion, createdHash)
	}
	createdRole := storedRoleSchema(t, store, "auditor")
	if !reflect.DeepEqual(createdRole.Permissions, identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")) || len(createdRole.FieldPermissions) != 0 {
		t.Fatalf("created role was not fail closed: %+v", createdRole)
	}
	replay := identityRolePolicyRequest(t, testServer, adminToken, http.MethodPost, "/identity/roles", "", "role-create-1", create)
	if replay.StatusCode != http.StatusCreated || replay.Header.Get("X-Resource-Hash") != createdHash || replay.Header.Get("X-Schema-Version") != createdVersion {
		t.Fatalf("role create replay status=%d revision=%s/%s", replay.StatusCode, replay.Header.Get("X-Schema-Version"), replay.Header.Get("X-Resource-Hash"))
	}
	_ = replay.Body.Close()
	assertRoleDefinitionEventRows(t, store, "auditor", "identity_role.created", 1, 1)

	permissionResponse := identityRolePolicyRequest(t, testServer, adminToken, http.MethodPut, "/identity/roles/auditor/permissions", createdHash, "role-permissions-1", identitymodel.IdentityRolePermissionPublicationRequest{
		Permissions:    identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "identity.roles.list"),
		BusinessReason: "restrict invoices to owned records",
	})
	if permissionResponse.StatusCode != http.StatusOK {
		t.Fatalf("permission publication status=%d body=%s", permissionResponse.StatusCode, readResponseBody(t, permissionResponse))
	}
	dataHash := permissionResponse.Header.Get("X-Resource-Hash")
	_ = permissionResponse.Body.Close()
	if dataHash == "" || dataHash == createdHash {
		t.Fatalf("permission publication hash=%q", dataHash)
	}
	afterData := storedRoleSchema(t, store, "auditor")
	if !reflect.DeepEqual(afterData.Permissions, identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOwner, "identity.roles.list")) {
		t.Fatalf("permission publication changed the wrong RoleSchema fields: %+v", afterData)
	}

	fieldResponse := identityRolePolicyRequest(t, testServer, adminToken, http.MethodPut, "/identity/roles/auditor/field-permissions", dataHash, "role-field-permissions-1", identitymodel.IdentityRoleFieldPermissionPublicationRequest{
		FieldPermissions: []identitymodel.IdentityFieldPermission{{Resource: "invoice", Field: "amount", Visible: true, Editable: false, Masked: true}},
		BusinessReason:   "mask invoice amounts",
	})
	if fieldResponse.StatusCode != http.StatusOK {
		t.Fatalf("field-permission publication status=%d body=%s", fieldResponse.StatusCode, readResponseBody(t, fieldResponse))
	}
	fieldHash := fieldResponse.Header.Get("X-Resource-Hash")
	_ = fieldResponse.Body.Close()
	afterField := storedRoleSchema(t, store, "auditor")
	if fieldHash == "" || fieldHash == dataHash || !reflect.DeepEqual(afterField.Permissions, afterData.Permissions) || len(afterField.FieldPermissions) != 1 || !afterField.FieldPermissions[0].Masked {
		t.Fatalf("field publication changed the wrong RoleSchema fields: hash=%q role=%+v", fieldHash, afterField)
	}
	assertRoleDefinitionEventRows(t, store, "auditor", "identity_role_permissions.published", 3, 1)
	assertRoleDefinitionEventRows(t, store, "auditor", "identity_role_field_permissions.published", 3, 1)

	updateResponse := identityRolePolicyRequest(t, testServer, adminToken, http.MethodPatch, "/identity/roles/auditor", fieldHash, "role-update-1", identitymodel.IdentityRoleDefinitionUpdateRequest{
		Name: "Audit viewer", Description: "Reviews audit evidence", BusinessReason: "use the approved role label",
	})
	if updateResponse.StatusCode != http.StatusOK {
		t.Fatalf("role update status=%d body=%s", updateResponse.StatusCode, readResponseBody(t, updateResponse))
	}
	updateHash := updateResponse.Header.Get("X-Resource-Hash")
	_ = updateResponse.Body.Close()
	afterUpdate := storedRoleSchema(t, store, "auditor")
	if updateHash == "" || updateHash == fieldHash || afterUpdate.Name != "Audit viewer" || afterUpdate.Description != "Reviews audit evidence" || !reflect.DeepEqual(afterUpdate.Permissions, afterField.Permissions) || !reflect.DeepEqual(afterUpdate.FieldPermissions, afterField.FieldPermissions) {
		t.Fatalf("role update did not preserve authorization policy: hash=%q role=%+v", updateHash, afterUpdate)
	}
	assertRoleDefinitionEventRows(t, store, "auditor", "identity_role.updated", 4, 1)

	deleteResponse := identityRolePolicyRequest(t, testServer, adminToken, http.MethodDelete, "/identity/roles/auditor", updateHash, "role-delete-1", identitymodel.IdentityRoleDefinitionDeleteRequest{
		BusinessReason: "retire the unused audit role",
	})
	if deleteResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("role delete status=%d body=%s", deleteResponse.StatusCode, readResponseBody(t, deleteResponse))
	}
	_ = deleteResponse.Body.Close()
	var projectionStatus string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT status FROM _identity_roles WHERE workspace_id = ? AND role_key = ?`, "workspace-primary", "auditor").Scan(&projectionStatus); err != nil {
		t.Fatal(err)
	}
	if projectionStatus != string(identitymodel.IdentityStatusDisabled) {
		t.Fatalf("deleted role projection status=%q", projectionStatus)
	}
	assertRoleDefinitionEventRows(t, store, "auditor", "identity_role.deleted", 4, 1)
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

func decodePermissionDefinitions(t *testing.T, response *http.Response) []identitymodel.IdentityPermissionDefinition {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("permission catalog status=%d body=%s", response.StatusCode, readResponseBody(t, response))
	}
	var permissions []identitymodel.IdentityPermissionDefinition
	if err := json.NewDecoder(response.Body).Decode(&permissions); err != nil {
		t.Fatal(err)
	}
	return permissions
}

func permissionDefinitionByKey(t *testing.T, permissions []identitymodel.IdentityPermissionDefinition, key string) identitymodel.IdentityPermissionDefinition {
	t.Helper()
	for _, permission := range permissions {
		if permission.Key == key {
			return permission
		}
	}
	t.Fatalf("permission %q not found", key)
	return identitymodel.IdentityPermissionDefinition{}
}

func rolePermissionConfiguration(t *testing.T, server *httptest.Server, accessToken, roleID string) ([]identitymodel.IdentityRolePermissionAssignment, string, string) {
	t.Helper()
	response := rolePermissionConfigurationResponse(t, server, accessToken, roleID)
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

func rolePermissionConfigurationResponse(t *testing.T, server *httptest.Server, accessToken, roleID string) *http.Response {
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
	return response
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
	payload, err := json.Marshal(identitymodel.IdentityRolePermissionPublicationRequest{
		Permissions:    identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, permissionKeys...),
		BusinessReason: reason,
	})
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

func identityRolePolicyRequest(t *testing.T, server *httptest.Server, accessToken, method, path, expectedHash, operationID string, body any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	if expectedHash != "" {
		request.Header.Set("Expected-Schema-Hash", expectedHash)
	}
	request.Header.Set("Idempotency-Key", operationID)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
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

func assertRoleDefinitionEventRows(t *testing.T, store *database.IdentityStore, roleKey, event string, wantVersions, wantAudits int) {
	t.Helper()
	var versions int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_role_definition_versions WHERE resource_type = ? AND resource_key = ?`, "role", roleKey).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != wantVersions {
		t.Fatalf("role %s definition version rows=%d want=%d", roleKey, versions, wantVersions)
	}
	var audits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND object_key = ? AND record_id = ?`, "workspace-primary", event, "role", roleKey).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != wantAudits {
		t.Fatalf("role %s event %s audit rows=%d want=%d", roleKey, event, audits, wantAudits)
	}
}
