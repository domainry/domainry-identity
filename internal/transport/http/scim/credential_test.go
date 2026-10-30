package scimhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSCIMBearerTokenSelectsWorkspaceAndProtectsDiscovery(t *testing.T) {
	credentials, err := newCredentialRegistry(map[string]string{"workspace-a": "workspace-a-secret", "workspace-b": "workspace-b-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if workspaceID, ok := credentials.authorize("Bearer workspace-b-secret"); !ok || workspaceID != "workspace-b" {
		t.Fatalf("workspace=%q authorized=%v", workspaceID, ok)
	}
	if _, ok := credentials.authorize("Bearer wrong-secret"); ok {
		t.Fatal("wrong SCIM bearer token was authorized")
	}

	handler := &Handler{credentials: credentials}
	protected := handler.authenticated(handler.serviceProviderConfig)
	unauthorized := httptest.NewRecorder()
	protected(unauthorized, httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" || unauthorized.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("unauthorized status=%d headers=%v body=%s", unauthorized.Code, unauthorized.Header(), unauthorized.Body.String())
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer workspace-a-secret")
	authorized := httptest.NewRecorder()
	protected(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(authorized.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	patch, _ := response["patch"].(map[string]any)
	etag, _ := response["etag"].(map[string]any)
	if patch["supported"] != true || etag["supported"] != true {
		t.Fatalf("service provider config=%v", response)
	}
}

func TestSCIMCredentialRegistryRejectsInvalidScopesAndTokenReuse(t *testing.T) {
	for name, configured := range map[string]map[string]string{
		"invalid workspace": {"default": "secret"},
		"empty token":       {"workspace-a": " "},
		"reused token":      {"workspace-a": "shared", "workspace-b": "shared"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newCredentialRegistry(configured); err == nil {
				t.Fatalf("configuration accepted: %v", configured)
			}
		})
	}
}

func TestSCIMListBoundsAreOneBasedAndBounded(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=3&count=5000", nil)
	startIndex, count, err := listBounds(request)
	if err != nil || startIndex != 3 || count != 1000 {
		t.Fatalf("start=%d count=%d err=%v", startIndex, count, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=0", nil)
	if _, _, err := listBounds(request); err == nil {
		t.Fatal("zero startIndex was accepted")
	}
}
