package scimhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

func TestSCIMResponseAttributeProjectionSupportsCoreExtensionAndMultiValues(t *testing.T) {
	active := true
	user := scimmodel.User{
		Schemas: []string{scimmodel.SchemaUser, scimmodel.SchemaEnterpriseUser}, ID: "user-1", UserName: "ada@example.com", DisplayName: "Ada", Active: &active,
		Name:           scimmodel.Name{GivenName: "Ada", FamilyName: "Lovelace"},
		Emails:         []scimmodel.MultiValue{{Value: "ada@example.com", Type: "work", Primary: true}},
		EnterpriseUser: &scimmodel.EnterpriseUser{EmployeeNumber: "E-1", Manager: &scimmodel.Manager{Value: "manager-1", DisplayName: "Manager"}},
		Meta:           scimmodel.Meta{ResourceType: "User", Version: `W/"1"`},
	}
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/user-1?attributes=userName,name.givenName,emails.value,"+scimmodel.SchemaEnterpriseUser+":manager.value", nil)
	projected, err := projectResponseAttributes(request, user)
	if err != nil {
		t.Fatal(err)
	}
	object := projected.(map[string]any)
	if object["id"] != "user-1" || object["userName"] != "ada@example.com" || object["displayName"] != nil || object["meta"] != nil {
		t.Fatalf("projected resource=%v", object)
	}
	name := object["name"].(map[string]any)
	if name["givenName"] != "Ada" || name["familyName"] != nil {
		t.Fatalf("projected name=%v", name)
	}
	emails := object["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["value"] != "ada@example.com" || emails[0].(map[string]any)["type"] != nil {
		t.Fatalf("projected emails=%v", emails)
	}
	enterprise := object[scimmodel.SchemaEnterpriseUser].(map[string]any)
	manager := enterprise["manager"].(map[string]any)
	if manager["value"] != "manager-1" || manager["displayName"] != nil {
		t.Fatalf("projected manager=%v", manager)
	}
	if len(object["schemas"].([]any)) != 2 {
		t.Fatalf("projected schemas=%v", object["schemas"])
	}
}

func TestSCIMResponseAttributeProjectionRejectsMutuallyExclusiveParameters(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/user-1?attributes=userName&excludedAttributes=name", nil)
	if _, err := projectResponseAttributes(request, scimmodel.User{}); err == nil {
		t.Fatal("mutually exclusive response parameters were accepted")
	}
}

func TestSCIMConditionalResourceResponseUsesETagAndContentLocation(t *testing.T) {
	handler := &Handler{}
	meta := scimmodel.Meta{Version: `W/"2"`, Location: "/scim/v2/Users/user-1"}
	request := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/user-1", nil)
	request.Header.Set("If-None-Match", meta.Version)
	response := httptest.NewRecorder()
	handler.writeResource(response, request, http.StatusOK, meta, scimmodel.User{Schemas: []string{scimmodel.SchemaUser}, ID: "user-1"})
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 || response.Header().Get("ETag") != meta.Version || response.Header().Get("Content-Location") != meta.Location {
		t.Fatalf("conditional response status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestETagHeaderMatchesListsAndWildcard(t *testing.T) {
	if !etagHeaderMatches(`W/"1", W/"2"`, `W/"2"`) || !etagHeaderMatches(`*`, `W/"2"`) {
		t.Fatal("valid If-None-Match value did not match")
	}
	if etagHeaderMatches(`W/"1"`, `W/"2"`) || etagHeaderMatches("", `W/"2"`) {
		t.Fatal("invalid If-None-Match value matched")
	}
}
