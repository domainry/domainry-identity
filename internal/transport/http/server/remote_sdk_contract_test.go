package httpserver_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/modulecapability"
	capabilitycontracttest "github.com/domainry/domainry-foundation/modulecapability/contracttest"
	identity "github.com/domainry/domainry-identity-sdk"
	identitycontracttest "github.com/domainry/domainry-identity-sdk/contracttest"
	identityremote "github.com/domainry/domainry-identity-sdk/remote"
	identitycapability "github.com/domainry/domainry-identity/capability"
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
	cfg.IdentityApplicationServiceCredentials = map[string]string{"workspace-primary/orders-runtime": serviceCredential, "tenant-primary/workspace-primary/domainry-notification": notificationCredential}

	identityServer, err := httpserver.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityServer.CloseContext(t.Context()) })
	testServer.Config.Handler = identityServer.Routes()
	testServer.Start()
	t.Cleanup(testServer.Close)
	if testServer.URL != issuer {
		t.Fatalf("test issuer=%q server URL=%q", issuer, testServer.URL)
	}
	unauthorizedRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/identity/runtime/directory/users", bytes.NewBufferString(`{"application":{"workspace_id":"workspace-primary","application_key":"orders-runtime"}}`))
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedRequest.Header.Set("Content-Type", "application/json")
	unauthorizedResponse, err := testServer.Client().Do(unauthorizedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("directory endpoint without service credential status=%d", unauthorizedResponse.StatusCode)
	}
	wrongScopeRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/identity/runtime/directory/users", bytes.NewBufferString(`{"application":{"workspace_id":"workspace-primary","application_key":"notify-runtime"}}`))
	if err != nil {
		t.Fatal(err)
	}
	wrongScopeRequest.Header.Set("Content-Type", "application/json")
	wrongScopeRequest.Header.Set("Authorization", "Bearer "+serviceCredential)
	wrongScopeResponse, err := testServer.Client().Do(wrongScopeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongScopeResponse.Body.Close()
	if wrongScopeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("directory endpoint accepted service credential for wrong application, status=%d", wrongScopeResponse.StatusCode)
	}
	sourceBinding, err := identitycapability.Open(identitycapability.Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSummary, err := sourceBinding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	factory := identityremote.NewFactory(identityremote.Config{
		Endpoint: testServer.URL, WorkspaceID: "workspace-primary", Issuer: issuer,
		Audience: "orders-runtime", ServiceAccessToken: serviceCredential,
		CapabilityContractSHA256: sourceSummary.Identity.ContractSHA256,
		HTTPClient:               testServer.Client(),
	})
	binding, err := factory.Open(t.Context(), identity.ApplicationRef{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	if binding.Descriptor().Mode != identity.DeploymentModeSaaS {
		t.Fatalf("mode=%q", binding.Descriptor().Mode)
	}
	capabilitycontracttest.VerifyBinding(t, binding)
	capabilitySummary, err := binding.CapabilitySummary(t.Context())
	if err != nil || capabilitySummary.Identity.Key != "identity" || capabilitySummary.Identity.ContractSHA256 == "" {
		t.Fatalf("capability summary=%+v err=%v", capabilitySummary, err)
	}
	validation, err := binding.ValidateCapabilityCandidate(t.Context(), modulecapability.ValidationRequest{
		ContractVersion: modulecapability.ValidationContractVersion, ModuleKey: "identity", CategoryKey: "identity.roles",
		ContractSHA256: capabilitySummary.Identity.ContractSHA256, Kind: "identity.role",
		Candidate: modulecapability.AuthoringFragment{Collection: "roles", Key: "sales", Value: []byte(`{"key":"sales","permissions":[],"record_scope":"all_records","unknown":true}`)},
	})
	if err != nil || len(validation.Diagnostics) == 0 || validation.Diagnostics[0].Owner != "identity" {
		t.Fatalf("capability validation=%+v err=%v", validation, err)
	}
	staleFactory := identityremote.NewFactory(identityremote.Config{
		Endpoint: testServer.URL, WorkspaceID: "workspace-primary", Issuer: issuer,
		Audience: "orders-runtime", ServiceAccessToken: serviceCredential,
		CapabilityContractSHA256: strings.Repeat("0", 64), HTTPClient: testServer.Client(),
	})
	if _, err := staleFactory.Open(t.Context(), identity.ApplicationRef{}); err == nil {
		t.Fatal("Identity Remote accepted a stale capability digest")
	}
	notificationFactory := identityremote.NewFactory(identityremote.Config{
		Endpoint: testServer.URL, TenantID: "tenant-primary", WorkspaceID: "workspace-primary", Issuer: issuer,
		Audience: "domainry-notification", ServiceAccessToken: notificationCredential,
		CapabilityContractSHA256: sourceSummary.Identity.ContractSHA256,
		HTTPClient:               testServer.Client(),
	})
	notificationBinding, err := notificationFactory.Open(t.Context(), identity.ApplicationRef{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notificationBinding.Close(t.Context()) })
	notificationCatalog := identity.AuthorizationCatalog{
		ContractVersion: identity.CatalogVersionV1,
		Application:     identity.ApplicationRef{TenantID: "tenant-primary", WorkspaceID: "workspace-primary", ApplicationKey: "domainry-notification"},
		Resources:       []identity.ResourceDefinition{{Key: "notification_event", SupportedFacts: []string{"tenant_id", "workspace_id", "application_key"}}},
		Actions:         []identity.ActionDefinition{{Resource: "notification_event", Action: "publish", ServiceCallable: true}},
	}
	if _, err := notificationBinding.Catalog().Publish(t.Context(), notificationCatalog); err != nil {
		t.Fatal(err)
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

	catalog := identity.AuthorizationCatalog{
		ContractVersion: identity.CatalogVersionV1,
		Application: identity.ApplicationRef{
			WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime",
			RedirectURLs: []string{"http://localhost:3100/auth/callback"},
		},
		Resources: []identity.ResourceDefinition{{Key: "customer", Fields: []string{"id", "owner_id"}, SupportedFacts: []string{"id", "owner_id"}}},
		Actions:   []identity.ActionDefinition{{Resource: "customer", Action: "read"}},
	}
	receipt, err := binding.Catalog().Publish(t.Context(), catalog)
	if err != nil || receipt.Revision == "" {
		t.Fatalf("publish receipt=%#v err=%v", receipt, err)
	}

	identitycontracttest.Run(t, identitycontracttest.Fixture{
		Binding: binding, WorkspaceID: "workspace-primary", ApplicationKey: "orders-runtime", Login: "admin@example.com", Password: "Domainry@2026",
		Resource: "customer", Action: "read", CatalogRevision: receipt.Revision,
	})
}
