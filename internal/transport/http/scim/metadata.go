package scimhttp

import (
	"net/http"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

const (
	schemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]any{
		"schemas":          []string{schemaServiceProviderConfig},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 1000},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer Token", "description": "Workspace-scoped static SCIM bearer token", "specUri": "https://www.rfc-editor.org/rfc/rfc6750", "primary": true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": "/scim/v2/ServiceProviderConfig"},
	})
}

func resourceTypeResources() []map[string]any {
	return []map[string]any{
		{
			"schemas": []string{schemaResourceType}, "id": "User", "name": "User", "description": "Domainry Identity user",
			"endpoint": "/Users", "schema": scimmodel.SchemaUser,
			"schemaExtensions": []map[string]any{{"schema": scimmodel.SchemaEnterpriseUser, "required": false}},
			"meta":             map[string]any{"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"},
		},
		{
			"schemas": []string{schemaResourceType}, "id": "Group", "name": "Group", "description": "External directory group",
			"endpoint": "/Groups", "schema": scimmodel.SchemaGroup,
			"meta": map[string]any{"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group"},
		},
	}
}

func (h *Handler) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	resources := resourceTypeResources()
	h.writeJSON(w, http.StatusOK, scimmodel.ListResponse{Schemas: []string{scimmodel.SchemaListResponse}, TotalResults: len(resources), StartIndex: 1, ItemsPerPage: len(resources), Resources: resources})
}

func (h *Handler) resourceType(w http.ResponseWriter, request *http.Request) {
	for _, resource := range resourceTypeResources() {
		if resource["id"] == request.PathValue("resourceType") {
			h.writeJSON(w, http.StatusOK, resource)
			return
		}
	}
	h.writeError(w, http.StatusNotFound, "", "SCIM resource type was not found")
}

func schemaResources() []map[string]any {
	attribute := func(name, attributeType string, multiValued, required bool, mutability, returned, uniqueness string, subAttributes ...map[string]any) map[string]any {
		value := map[string]any{
			"name": name, "type": attributeType, "multiValued": multiValued, "required": required,
			"caseExact": false, "mutability": mutability, "returned": returned, "uniqueness": uniqueness,
		}
		if len(subAttributes) != 0 {
			value["subAttributes"] = subAttributes
		}
		return value
	}
	stringSub := func(name string) map[string]any {
		return attribute(name, "string", false, false, "readWrite", "default", "none")
	}
	user := map[string]any{
		"schemas": []string{schemaSchema}, "id": scimmodel.SchemaUser, "name": "User", "description": "Domainry Identity SCIM user",
		"attributes": []map[string]any{
			attribute("userName", "string", false, true, "readWrite", "default", "server"),
			attribute("name", "complex", false, false, "readWrite", "default", "none", stringSub("formatted"), stringSub("familyName"), stringSub("givenName"), stringSub("middleName"), stringSub("honorificPrefix"), stringSub("honorificSuffix")),
			attribute("displayName", "string", false, false, "readWrite", "default", "none"),
			attribute("active", "boolean", false, false, "readWrite", "default", "none"),
			attribute("emails", "complex", true, true, "readWrite", "default", "none", stringSub("value"), stringSub("type"), attribute("primary", "boolean", false, false, "readWrite", "default", "none")),
			attribute("phoneNumbers", "complex", true, false, "readWrite", "default", "none", stringSub("value"), stringSub("type"), attribute("primary", "boolean", false, false, "readWrite", "default", "none")),
			attribute("preferredLanguage", "string", false, false, "readWrite", "default", "none"),
			attribute("locale", "string", false, false, "readWrite", "default", "none"),
			attribute("timezone", "string", false, false, "readWrite", "default", "none"),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + scimmodel.SchemaUser},
	}
	group := map[string]any{
		"schemas": []string{schemaSchema}, "id": scimmodel.SchemaGroup, "name": "Group", "description": "External directory group; it is not an authorization role",
		"attributes": []map[string]any{
			attribute("displayName", "string", false, true, "readWrite", "default", "none"),
			attribute("members", "complex", true, false, "readWrite", "default", "none", attribute("value", "string", false, true, "immutable", "default", "none"), attribute("$ref", "reference", false, false, "immutable", "default", "none"), attribute("display", "string", false, false, "readOnly", "default", "none")),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + scimmodel.SchemaGroup},
	}
	enterprise := map[string]any{
		"schemas": []string{schemaSchema}, "id": scimmodel.SchemaEnterpriseUser, "name": "EnterpriseUser", "description": "Enterprise user attributes",
		"attributes": []map[string]any{
			attribute("employeeNumber", "string", false, false, "readWrite", "default", "none"),
			attribute("department", "string", false, false, "readWrite", "default", "none"),
			attribute("manager", "complex", false, false, "readWrite", "default", "none", stringSub("value"), attribute("$ref", "reference", false, false, "readOnly", "default", "none"), attribute("displayName", "string", false, false, "readOnly", "default", "none")),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + scimmodel.SchemaEnterpriseUser},
	}
	return []map[string]any{user, group, enterprise}
}

func (h *Handler) schemas(w http.ResponseWriter, _ *http.Request) {
	resources := schemaResources()
	h.writeJSON(w, http.StatusOK, scimmodel.ListResponse{Schemas: []string{scimmodel.SchemaListResponse}, TotalResults: len(resources), StartIndex: 1, ItemsPerPage: len(resources), Resources: resources})
}

func (h *Handler) schema(w http.ResponseWriter, request *http.Request) {
	for _, resource := range schemaResources() {
		if resource["id"] == request.PathValue("schema") {
			h.writeJSON(w, http.StatusOK, resource)
			return
		}
	}
	h.writeError(w, http.StatusNotFound, "", "SCIM schema was not found")
}
