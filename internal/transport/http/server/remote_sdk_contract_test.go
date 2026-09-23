package httpserver_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
	identitycontracttest "github.com/domainry/domainry-identity-sdk/contracttest"
	identityremote "github.com/domainry/domainry-identity-sdk/remote"
	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

func TestRemoteSDKBindingAgainstRealIdentityHTTPServer(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", ".."))

	testServer := httptest.NewUnstartedServer(nil)
	issuer := "http://" + testServer.Listener.Addr().String()
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	cfg.AuthIssuer = issuer
	cfg.AuthAudience = "domainry-runtime"
	cfg.IdentityWorkspaceID = "workspace-primary"
	serviceCredential := "runtime-service-token"
	notificationCredential := "notification-service-token"
	cfg.IdentityApplicationServiceCredentials = map[string]string{"workspace-primary/orders-runtime": serviceCredential, "workspace-primary/domainry-notification": notificationCredential}
	cfg.IdentityApplicationPermissionOwners = map[string][]string{"workspace-primary/orders-runtime": {"application:orders-runtime", "application:other-runtime"}}
	cfg.IdentityApplicationServicePolicies = map[string][]string{"workspace-primary/orders-runtime": {"audience:domainry-notification", "grant:notification_event.publish"}}

	identityServer, err := httpserver.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	ownerDB, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })
	testServer.Config.Handler = identityServer.Routes()
	testServer.Start()
	t.Cleanup(testServer.Close)
	if testServer.URL != issuer {
		t.Fatalf("test issuer=%q server URL=%q", issuer, testServer.URL)
	}
	unauthorizedRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/identity/users/query", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedRequest.Header.Set("Content-Type", "application/json")
	unauthorizedRequest.Header.Set("X-Workspace-ID", "workspace-primary")
	unauthorizedRequest.Header.Set("X-Domainry-Application-Key", "orders-runtime")
	unauthorizedResponse, err := testServer.Client().Do(unauthorizedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("projection endpoint without service credential status=%d", unauthorizedResponse.StatusCode)
	}
	wrongScopeRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/identity/users/query", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongScopeRequest.Header.Set("Content-Type", "application/json")
	wrongScopeRequest.Header.Set("Authorization", "Bearer "+serviceCredential)
	wrongScopeRequest.Header.Set("X-Workspace-ID", "workspace-primary")
	wrongScopeRequest.Header.Set("X-Domainry-Application-Key", "notify-runtime")
	wrongScopeResponse, err := testServer.Client().Do(wrongScopeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongScopeResponse.Body.Close()
	if wrongScopeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("projection endpoint accepted service credential for wrong application, status=%d", wrongScopeResponse.StatusCode)
	}
	factory := identityremote.NewFactory(identityremote.Config{
		Endpoint: testServer.URL, WorkspaceID: "workspace-primary", Issuer: issuer,
		Audience: "orders-runtime", ServiceAccessToken: serviceCredential,
		HTTPClient: testServer.Client(),
	})
	binding, err := factory.Open(t.Context(), identity.ApplicationRef{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	if binding.Descriptor().Mode != identity.DeploymentModeSaaS {
		t.Fatalf("mode=%q", binding.Descriptor().Mode)
	}
	ordersApplication := identity.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime"}
	if _, err := binding.Applications().Register(t.Context(), identity.ApplicationRegistration{
		Application: ordersApplication, RedirectURLs: []string{"http://localhost:3100/auth/callback"},
	}); err != nil {
		t.Fatalf("register orders application: %v", err)
	}
	permissionRequest, err := identity.NewPermissionReconcileRequest(ordersApplication, "application:orders-runtime", "", []identity.PermissionDefinition{{PermissionKey: "customer.read", ResourceKey: "customer", OperationKey: "read", Label: "Read customers", Category: "Orders", SourceKind: "object_action"}})
	if err != nil {
		t.Fatal(err)
	}
	permissionReceipt, err := binding.Permissions().Reconcile(t.Context(), permissionRequest)
	if err != nil || permissionReceipt.SourceOwner != "application:orders-runtime" || permissionReceipt.PreviousSnapshotHash != "" || permissionReceipt.SnapshotHash != permissionRequest.SnapshotHash || permissionReceipt.DefinitionCount != 1 || permissionReceipt.Inserted != 1 {
		t.Fatalf("reconcile orders permission receipt=%+v err=%v", permissionReceipt, err)
	}
	snapshotReader, ok := binding.Permissions().(identity.PermissionSnapshotReader)
	if !ok {
		t.Fatal("remote permission registry has no source snapshot reader")
	}
	snapshotRequest := identity.PermissionSourceSnapshotRequest{Application: ordersApplication, SourceOwner: permissionRequest.SourceOwner}
	snapshot, err := snapshotReader.CurrentSourceSnapshot(t.Context(), snapshotRequest)
	if err != nil || snapshot.ValidateFor(snapshotRequest) != nil || snapshot.SnapshotHash != permissionReceipt.SnapshotHash {
		t.Fatalf("remote permission source snapshot=%+v err=%v", snapshot, err)
	}
	updatedDefinitions := append([]identity.PermissionDefinition(nil), permissionRequest.Definitions...)
	updatedDefinitions[0].Label = "Read current customers"
	updatedRequest, err := identity.NewPermissionReconcileRequest(ordersApplication, permissionRequest.SourceOwner, permissionReceipt.SnapshotHash, updatedDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	updatedReceipt, err := binding.Permissions().Reconcile(t.Context(), updatedRequest)
	if err != nil || updatedReceipt.PreviousSnapshotHash != permissionReceipt.SnapshotHash || updatedReceipt.SnapshotHash != updatedRequest.SnapshotHash || updatedReceipt.DefinitionCount != 1 || updatedReceipt.Updated != 1 {
		t.Fatalf("update orders permission receipt=%+v err=%v", updatedReceipt, err)
	}
	if _, err := binding.Permissions().Reconcile(t.Context(), permissionRequest); err == nil {
		t.Fatal("out-of-order remote permission snapshot was accepted")
	} else {
		var sdkError *identity.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusConflict || sdkError.Code != "identity.permission_snapshot_stale" {
			t.Fatalf("stale remote permission error=%#v", err)
		}
	}
	conflictingRequest, err := identity.NewPermissionReconcileRequest(ordersApplication, "application:other-runtime", "", updatedDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Permissions().Reconcile(t.Context(), conflictingRequest); err == nil {
		t.Fatal("remote permission owner conflict was accepted")
	} else {
		var sdkError *identity.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusConflict || sdkError.Code != "identity.permission_owner_conflict" {
			t.Fatalf("remote permission owner conflict error=%#v", err)
		}
	}
	forbiddenOwnerRequest, err := identity.NewPermissionReconcileRequest(ordersApplication, "application:forbidden-runtime", "", updatedDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Permissions().Reconcile(t.Context(), forbiddenOwnerRequest); err == nil {
		t.Fatal("service credential published an owner outside its configured scope")
	} else {
		var sdkError *identity.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusForbidden || sdkError.Code != "identity.permission_source_owner_forbidden" {
			t.Fatalf("forbidden permission owner error=%#v", err)
		}
	}
	if _, err := snapshotReader.CurrentSourceSnapshot(t.Context(), identity.PermissionSourceSnapshotRequest{Application: ordersApplication, SourceOwner: "application:forbidden-runtime"}); err == nil {
		t.Fatal("service credential read an owner snapshot outside its configured scope")
	} else {
		var sdkError *identity.Error
		if !errors.As(err, &sdkError) || sdkError.StatusCode != http.StatusForbidden || sdkError.Code != "identity.permission_source_owner_forbidden" {
			t.Fatalf("forbidden permission source snapshot error=%#v", err)
		}
	}
	rawPermissionRequest, err := json.Marshal(updatedRequest)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryUserRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPut, testServer.URL+"/identity/permissions/reconcile", bytes.NewReader(rawPermissionRequest))
	if err != nil {
		t.Fatal(err)
	}
	ordinaryUserRequest.Header.Set("Content-Type", "application/json")
	ordinaryUserRequest.Header.Set("Authorization", "Bearer ordinary-user-token")
	ordinaryUserResponse, err := testServer.Client().Do(ordinaryUserRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = ordinaryUserResponse.Body.Close()
	if ordinaryUserResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ordinary user token published permission definitions, status=%d", ordinaryUserResponse.StatusCode)
	}
	notificationFactory := identityremote.NewFactory(identityremote.Config{
		Endpoint: testServer.URL, WorkspaceID: "workspace-primary", Issuer: issuer,
		Audience: "domainry-notification", ServiceAccessToken: notificationCredential,
		HTTPClient: testServer.Client(),
	})
	notificationBinding, err := notificationFactory.Open(t.Context(), identity.ApplicationRef{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notificationBinding.Close(t.Context()) })
	notificationApplication := identity.ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "domainry-notification"}
	if _, err := notificationBinding.Applications().Register(t.Context(), identity.ApplicationRegistration{Application: notificationApplication}); err != nil {
		t.Fatalf("register notification application: %v", err)
	}
	callerServices := binding.(identity.ApplicationServiceBinding).ApplicationServices()
	grant := identity.ApplicationServiceGrant{Resource: "notification_event", Action: "publish"}
	serviceToken, err := callerServices.Exchange(t.Context(), identity.ExchangeApplicationServiceTokenRequest{Audience: "domainry-notification", Grants: []identity.ApplicationServiceGrant{grant}})
	if err != nil || serviceToken.AccessToken == "" || serviceToken.CredentialID != "default" {
		t.Fatalf("service token=%+v err=%v", serviceToken, err)
	}
	resourceServices := notificationBinding.(identity.ApplicationServiceBinding).ApplicationServices()
	servicePrincipal, err := resourceServices.Verify(t.Context(), identity.VerifyApplicationServiceTokenRequest{AccessToken: serviceToken.AccessToken, Grant: grant})
	if err != nil || servicePrincipal.SubjectID != "service:orders-runtime" || servicePrincipal.Application.ApplicationKey != "orders-runtime" || servicePrincipal.Audience != "domainry-notification" {
		t.Fatalf("service principal=%+v err=%v", servicePrincipal, err)
	}
	if _, err := resourceServices.Verify(t.Context(), identity.VerifyApplicationServiceTokenRequest{AccessToken: serviceToken.AccessToken, Grant: identity.ApplicationServiceGrant{Resource: "notification_governance", Action: "read"}}); err == nil {
		t.Fatal("service token authorized an unissued grant")
	}

	identitycontracttest.Run(t, identitycontracttest.Fixture{
		Binding: binding, WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime", Login: "admin@example.com", Password: "Domainry@2026",
		Resource: "identity.users", Action: "list", DataAllowed: true,
	})
	login, err := binding.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: "workspace-primary", Login: "admin@example.com", Password: "Domainry@2026"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := binding.Authentication().CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: login.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	subjects, ok := binding.(identity.SystemSubjectBinding)
	if !ok {
		t.Fatal("remote subject lifecycle unavailable")
	}
	erase := identity.SubjectErasureRequest{WorkspaceID: "workspace-primary", SubjectID: session.User.ID, RequestID: "erase-http-admin"}
	if _, err = ownerDB.ExecContext(t.Context(), `INSERT INTO _subject_requests(id,workspace_id,request_type,kind,status,subject_id,resolved_identity,updated_at,payload_json) VALUES(?,?,'subject_request','erase','executing',?,?,?,'{}')`, erase.RequestID, erase.WorkspaceID, erase.SubjectID, erase.SubjectID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err = ownerDB.ExecContext(t.Context(), `INSERT INTO _subject_steps(workspace_id,request_id,owner,operation,payload_json,completed_at) VALUES(?,?,'lifecycle','erase_fence','{}',?)`, erase.WorkspaceID, erase.RequestID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(erase)
	if err != nil {
		t.Fatal(err)
	}
	userRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/identity/system/subjects/erase", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	userRequest.Header.Set("Content-Type", "application/json")
	userRequest.Header.Set("X-Domainry-Workspace-ID", "workspace-primary")
	userRequest.Header.Set("X-Domainry-Application-Key", "orders-runtime")
	userRequest.Header.Set("Authorization", "Bearer "+login.AccessToken)
	userResponse, err := testServer.Client().Do(userRequest)
	if err != nil {
		t.Fatal(err)
	}
	userResponse.Body.Close()
	if userResponse.StatusCode != http.StatusUnauthorized && userResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("user bearer reached subject erasure: %d", userResponse.StatusCode)
	}
	wrong := erase
	wrong.WorkspaceID = "other-workspace"
	if _, err = subjects.SystemSubjects().EraseSubjectForRequest(t.Context(), wrong); err == nil {
		t.Fatal("remote cross-workspace erasure accepted")
	}
	held := erase
	held.LegalHolds = json.RawMessage(`[{}]`)
	if _, err = subjects.SystemSubjects().EraseSubjectForRequest(t.Context(), held); err == nil {
		t.Fatal("remote legal hold ignored")
	}
	first, err := subjects.SystemSubjects().EraseSubjectForRequest(t.Context(), erase)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := subjects.SystemSubjects().EraseSubjectForRequest(t.Context(), erase)
	if err != nil || string(first) != string(replay) {
		t.Fatalf("remote erasure receipt changed: %s %s %v", first, replay, err)
	}
	if _, err = binding.Authentication().CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: login.AccessToken}); err == nil {
		t.Fatal("remote erased session remains active")
	}

}
