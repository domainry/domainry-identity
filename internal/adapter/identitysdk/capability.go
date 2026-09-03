package identitysdkadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// NewCapabilityBinding builds Identity's immutable, topology-neutral
// capability contract without opening the operational SDK binding.
func NewCapabilityBinding() (*modulecapability.StaticBinding, error) {
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		return nil, fmt.Errorf("build Identity Action registry for capability projection: %w", err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		return nil, fmt.Errorf("project Identity authoring Actions: %w", err)
	}
	domain := projection.Domain()
	definitions := append([]authoringcontract.CapabilityAuthoringDefinition(nil), domain.Capabilities...)
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Key < definitions[j].Key })

	type selectedRoute struct {
		definition authoringcontract.CapabilityAuthoringDefinition
		action     identitymodel.IdentityActionDefinition
		method     string
		path       string
		score      int
	}
	routes := map[string]selectedRoute{}
	for _, definition := range definitions {
		for _, pattern := range definition.ConfigurationRoutes {
			method, path, found := strings.Cut(strings.TrimSpace(pattern), " ")
			method, path = strings.ToLower(strings.TrimSpace(method)), strings.TrimSpace(path)
			if !found || method == "" || path == "" {
				return nil, fmt.Errorf("Identity capability %q has invalid route %q", definition.Key, pattern)
			}
			key := strings.ToUpper(method) + " " + path
			action, found := projection.ActionForRoute(key)
			if !found {
				return nil, fmt.Errorf("Identity capability %q route %q has no projected Action", definition.Key, key)
			}
			candidate := selectedRoute{definition: definition, action: action, method: method, path: path, score: identityRouteOwnershipScore(definition, key)}
			if current, exists := routes[key]; !exists || candidate.score > current.score {
				routes[key] = candidate
			} else if candidate.score == current.score && candidate.score > 1 && candidate.definition.Key != current.definition.Key {
				return nil, fmt.Errorf("Identity capability route %s has multiple source owners", key)
			}
		}
	}
	definitionsByCategory := map[string][]authoringcontract.CapabilityAuthoringDefinition{}
	providedCapabilities := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		categoryKey := identityCapabilityCategory(definition.Key)
		definitionsByCategory[categoryKey] = append(definitionsByCategory[categoryKey], definition)
		providedCapabilities = append(providedCapabilities, definition.Key)
	}
	routesByCategory := map[string][]selectedRoute{}
	for _, selected := range routes {
		categoryKey := identityCapabilityCategory(selected.definition.Key)
		routesByCategory[categoryKey] = append(routesByCategory[categoryKey], selected)
	}
	documents := make([]modulecapability.CategoryDocument, 0, len(definitionsByCategory))
	categoryKeys := make([]string, 0, len(definitionsByCategory))
	for key := range definitionsByCategory {
		categoryKeys = append(categoryKeys, key)
	}
	sort.Strings(categoryKeys)
	for _, categoryKey := range categoryKeys {
		categoryDefinitions := definitionsByCategory[categoryKey]
		categoryRoutes := routesByCategory[categoryKey]
		sort.Slice(categoryRoutes, func(i, j int) bool {
			left := strings.ToUpper(categoryRoutes[i].method) + " " + categoryRoutes[i].path
			right := strings.ToUpper(categoryRoutes[j].method) + " " + categoryRoutes[j].path
			return left < right
		})
		paths := map[string]map[string]json.RawMessage{}
		components := map[string]map[string]json.RawMessage{
			"schemas": {},
			"securitySchemes": {
				"BearerAuth": json.RawMessage(`{"type":"http","scheme":"bearer","bearerFormat":"JWT"}`),
			},
		}
		validationScopes := []string{}
		validationContracts := []modulecapability.ValidationScopeContract{}
		for _, definition := range categoryDefinitions {
			if definition.Key == "identity.role" {
				validationScopes = append(validationScopes, definition.Key)
				validationContracts = append(validationContracts, modulecapability.ValidationScopeContract{
					Kind: "identity.role", Description: "Validate one complete project role definition and its embedded permission/data/field policy.",
					Coverage: modulecapability.ValidationCoverageAllCandidates, CandidateCollections: []string{"roles"}, ReferencedCollections: []string{"objects", "permissions"},
				})
			}
			inputName, outputName := identitySchemaNames(definition.Key)
			if definition.InputSchema != nil {
				raw, err := identityOpenAPISchema(definition.InputSchema, inputName)
				if err != nil {
					return nil, err
				}
				components["schemas"][inputName] = raw
			}
			if definition.OutputSchema != nil {
				raw, err := identityOpenAPISchema(definition.OutputSchema, outputName)
				if err != nil {
					return nil, err
				}
				components["schemas"][outputName] = raw
			}
		}
		for _, selected := range categoryRoutes {
			inputName, outputName := identitySchemaNames(selected.definition.Key)
			if paths[selected.path] == nil {
				paths[selected.path] = map[string]json.RawMessage{}
			}
			operation, err := identityOpenAPIOperation(selected.definition, selected.action, selected.method, selected.path, inputName, outputName)
			if err != nil {
				return nil, err
			}
			paths[selected.path][selected.method] = operation
		}
		name, description := identityCategoryText(categoryKey)
		category := modulecapability.CategorySummary{
			Key: categoryKey, Name: name, Description: description,
			OperationCount:   len(categoryRoutes),
			AssemblyChains:   []string{"identity_before_authorization_and_application_publication"},
			ValidationScopes: validationScopes,
		}
		documents = append(documents, modulecapability.CategoryDocument{Category: category, OpenAPI: modulecapability.OpenAPIFragment{OpenAPI: "3.1.0", Paths: paths, Components: components}, ValidationContracts: validationContracts})
	}
	summary := modulecapability.ModuleSummary{
		Identity: modulecapability.ModuleIdentity{
			Key: "identity", SourceOwner: "identity", ModuleVersion: identitysdk.CurrentProtocolVersion,
			ValidationRevision:       "identity-authoring-validation-v1",
			SupportedDeploymentModes: []modulecapability.DeploymentMode{modulecapability.DeploymentModeModule, modulecapability.DeploymentModeSaaS},
		},
		Name:        "Identity",
		Description: "Authentication, principals, users, organizational identity, roles, permissions, and access-policy configuration.",
		Scenarios: modulecapability.AdaptationScenarios{
			UseWhen: []string{
				"The product has authenticated users, service identities, roles, permissions, or organization units",
				"The product requires login, external identity providers, application profile binding, or governed access",
			},
			DoNotUseWhen: []string{
				"The requirement only stores a business contact or organization without authentication or access control",
				"The requirement only sends a user-facing message; notification delivery is owned by Notification",
			},
			RequirementSignals:   []string{"login and session", "user or service identity", "role and permission", "organization unit", "OIDC or SAML provider"},
			ProvidedCapabilities: append([]string(nil), providedCapabilities...),
			RequiredModules:      []string{}, OptionalModules: []string{}, ConflictingModules: []string{},
			AssemblyChains:    []string{"identity_before_authorization_and_application_publication"},
			ValidationScopes:  []string{"identity.role"},
			SelectionExamples: []modulecapability.ScenarioExample{{Requirement: "Employees sign in and receive organization-scoped permissions", Reason: "Identity owns authentication, users, organization units, roles, and access policy"}},
			RejectionExamples: []modulecapability.ScenarioExample{{Requirement: "Store customer companies and contacts without login", Reason: "This does not require an Identity principal"}},
		},
	}
	return modulecapability.NewStaticBinding(summary, documents, identityCandidateValidator(definitions))
}

func identityCapabilityCategory(capabilityKey string) string {
	switch capabilityKey {
	case "identity.user", "identity.organization_unit":
		return "identity.directory"
	case "identity.profile_binding":
		return "identity.directory"
	case "identity.role", "identity.role_permission", "identity.user_role_assignment":
		return "identity.roles"
	default:
		return "identity.access_policy"
	}
}

func identityCategoryText(key string) (string, string) {
	switch key {
	case "identity.directory":
		return "Identity directory", "Configure authenticated users and organization units."
	case "identity.roles":
		return "Identity roles", "Configure roles, permission grants, and user-role assignments."
	default:
		return "Identity access policy", "Configure data scopes, field permissions, menus, and role-menu access policy."
	}
}

func identityRouteOwnershipScore(definition authoringcontract.CapabilityAuthoringDefinition, endpoint string) int {
	for _, owned := range []string{definition.ValidationEndpoint, definition.PreviewEndpoint, definition.SimulationEndpoint} {
		if strings.TrimSpace(owned) == endpoint {
			return 3
		}
	}
	if operations := definition.ResourceOperations; operations != nil {
		for _, owned := range []string{operations.Validate, operations.Upsert, operations.Get, operations.Versions, operations.Simulate, operations.Rollback, operations.Delete} {
			if strings.TrimSpace(owned) == endpoint {
				return 3
			}
		}
	}
	return 1
}

func identityOpenAPIOperation(definition authoringcontract.CapabilityAuthoringDefinition, action identitymodel.IdentityActionDefinition, method, path, inputName, outputName string) (json.RawMessage, error) {
	effect := modulecapability.EffectClass(action.EffectClass)
	if effect != modulecapability.EffectRead && effect != modulecapability.EffectWrite {
		return nil, fmt.Errorf("Identity authoring Action %q has invalid effect %q", action.Key, action.EffectClass)
	}
	idempotency := modulecapability.Idempotency{Mode: strings.TrimSpace(action.IdempotencyDecision)}
	if idempotency.Mode == "" {
		return nil, fmt.Errorf("Identity authoring Action %q has no idempotency decision", action.Key)
	}
	if definition.ResourceOperations != nil && strings.TrimSpace(definition.ResourceOperations.Upsert) == strings.ToUpper(method)+" "+path {
		for _, header := range definition.ResourceOperations.UpsertHeaders {
			if strings.EqualFold(header.Name, "Idempotency-Key") {
				idempotency.KeySource = header.Name
			}
		}
	}
	authorization := modulecapability.Authorization{
		Strategy: action.Authorization.Strategy, PolicyKey: action.Authorization.PolicyKey,
		Audiences: append([]string(nil), action.Authorization.Audiences...),
	}
	if authorization.Strategy != actioncontract.AuthorizationAnonymous {
		authorization.WorkspaceScope = "application_workspace"
	}
	if action.Permission != nil {
		if action.Permission.Key != action.Key {
			return nil, fmt.Errorf("Identity authoring Action %q does not own its same-key Permission", action.Key)
		}
		authorization.Permission = action.Permission.Key
	}
	extension := modulecapability.OperationExtension{Owner: "identity", Authorization: authorization, Effect: effect, Idempotency: idempotency}
	operation := map[string]any{
		"operationId":                          identityOperationID(definition.Key, method, path),
		"tags":                                 []string{definition.Key},
		"summary":                              identityOperationSummary(definition.Key, method, path),
		"description":                          "Identity-owned " + strings.ReplaceAll(definition.Lifecycle, "_", " ") + " operation.",
		modulecapability.OperationExtensionKey: extension,
	}
	if authorization.Strategy == actioncontract.AuthorizationAnonymous {
		operation["security"] = []any{}
	} else {
		operation["security"] = []any{map[string]any{"BearerAuth": []any{}}}
	}
	parameters := identityPathParameters(path)
	if len(parameters) != 0 {
		operation["parameters"] = parameters
	}
	if identityOperationAcceptsBody(definition, method, path) && definition.InputSchema != nil {
		content := map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/" + inputName}}
		if len(definition.Examples) != 0 {
			examples := map[string]any{}
			for _, example := range definition.Examples {
				examples[example.Name] = map[string]any{"value": example.Value}
			}
			content["examples"] = examples
		}
		operation["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": content}}
	}
	responses := map[string]any{}
	if method == strings.ToLower(http.MethodDelete) {
		responses["204"] = map[string]any{"description": "Identity resource removed"}
	} else {
		success := map[string]any{"description": "Identity operation result"}
		if definition.OutputSchema != nil && !strings.EqualFold(strings.TrimSpace(definition.ValidationEndpoint), strings.ToUpper(method)+" "+path) {
			schema := map[string]any{"$ref": "#/components/schemas/" + outputName}
			if definition.ResourceOperations != nil && strings.TrimSpace(definition.ResourceOperations.Versions) == strings.ToUpper(method)+" "+path {
				schema = map[string]any{"type": "array", "items": schema}
			}
			success["content"] = map[string]any{"application/json": map[string]any{"schema": schema}}
		}
		responses["200"] = success
	}
	responses["400"] = map[string]any{"description": "Invalid Identity candidate"}
	responses["401"] = map[string]any{"description": "Authentication required"}
	responses["403"] = map[string]any{"description": "Identity permission denied"}
	operation["responses"] = responses
	payload, err := json.Marshal(operation)
	return json.RawMessage(payload), err
}

func identityOperationAcceptsBody(definition authoringcontract.CapabilityAuthoringDefinition, method, path string) bool {
	if method != strings.ToLower(http.MethodPost) && method != strings.ToLower(http.MethodPut) && method != strings.ToLower(http.MethodPatch) {
		return false
	}
	endpoint := strings.ToUpper(method) + " " + path
	if strings.HasSuffix(path, "/enable") || strings.HasSuffix(path, "/disable") {
		return false
	}
	return endpoint == strings.TrimSpace(definition.ValidationEndpoint) || definition.ResourceOperations == nil || endpoint == strings.TrimSpace(definition.ResourceOperations.Upsert)
}

func identityPathParameters(path string) []any {
	parameters := []any{}
	for remaining := path; ; {
		start := strings.IndexByte(remaining, '{')
		if start < 0 {
			break
		}
		end := strings.IndexByte(remaining[start+1:], '}')
		if end < 0 {
			break
		}
		name := remaining[start+1 : start+1+end]
		parameters = append(parameters, map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string", "minLength": 1}})
		remaining = remaining[start+end+2:]
	}
	return parameters
}

func identitySchemaNames(key string) (string, string) {
	base := "Identity" + identityUpperCamel(strings.TrimPrefix(key, "identity."))
	return base + "Input", base + "Output"
}

func identityOpenAPISchema(schema *authoringcontract.CapabilityAuthoringSchema, componentName string) (json.RawMessage, error) {
	payload, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	rewriteIdentitySchemaReferences(value, componentName)
	payload, err = json.Marshal(value)
	return json.RawMessage(payload), err
}

func rewriteIdentitySchemaReferences(value any, componentName string) {
	switch typed := value.(type) {
	case map[string]any:
		if ref, ok := typed["$ref"].(string); ok && strings.HasPrefix(ref, "#/$defs/") {
			typed["$ref"] = "#/components/schemas/" + componentName + strings.TrimPrefix(ref, "#")
		}
		for _, child := range typed {
			rewriteIdentitySchemaReferences(child, componentName)
		}
	case []any:
		for _, child := range typed {
			rewriteIdentitySchemaReferences(child, componentName)
		}
	}
}

func identityOperationID(key, method, path string) string {
	return "identity" + identityUpperCamel(strings.TrimPrefix(key, "identity.")) + identityUpperCamel(method+" "+path)
}

func identityOperationSummary(key, method, path string) string {
	return strings.ToUpper(method) + " " + strings.ReplaceAll(strings.TrimPrefix(key, "identity."), "_", " ") + " at " + path
}

func identityUpperCamel(value string) string {
	var result strings.Builder
	upper := true
	for _, character := range value {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			upper = true
			continue
		}
		if upper {
			character = unicode.ToUpper(character)
			upper = false
		}
		result.WriteRune(character)
	}
	return result.String()
}

func identityCandidateValidator(definitions []authoringcontract.CapabilityAuthoringDefinition) modulecapability.Validator {
	byKey := make(map[string]authoringcontract.CapabilityAuthoringDefinition, len(definitions))
	for _, definition := range definitions {
		byKey[definition.Key] = definition
	}
	return func(_ context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
		definition, found := byKey[request.Kind]
		if !found || definition.InputSchema == nil {
			return modulecapability.ValidationResult{}, &modulecapability.Error{StatusCode: http.StatusBadRequest, Code: "identity.capability_kind_invalid"}
		}
		schema := *definition.InputSchema
		if request.Kind == "identity.role" {
			payload, exists := schema.Properties["payload"]
			if !exists {
				return modulecapability.ValidationResult{}, &modulecapability.Error{StatusCode: http.StatusInternalServerError, Code: "identity.capability_schema_invalid"}
			}
			schema = payload
		}
		var candidate map[string]any
		if err := modulecapability.DecodeAuthoringValue(request.Candidate, &candidate); err != nil {
			return modulecapability.ValidationResult{}, &modulecapability.Error{StatusCode: http.StatusBadRequest, Code: "identity.capability_candidate_invalid", Message: err.Error()}
		}
		diagnostics := []modulecapability.Diagnostic{}
		if key, declared := candidate["key"]; declared && strings.TrimSpace(fmt.Sprint(key)) != request.Candidate.Key {
			addIdentityDiagnostic(&diagnostics, "identity.validation.source_key", "$.candidate.value.key", "Identity role value key must equal the source fragment key", map[string]string{"expected": request.Candidate.Key})
		} else if !declared {
			candidate["key"] = request.Candidate.Key
		}
		validateIdentitySchema(schema, schema, candidate, "$.candidate.value", &diagnostics)
		sort.Slice(diagnostics, func(i, j int) bool {
			if diagnostics[i].FieldPath == diagnostics[j].FieldPath {
				return diagnostics[i].RuleKey < diagnostics[j].RuleKey
			}
			return diagnostics[i].FieldPath < diagnostics[j].FieldPath
		})
		return modulecapability.ValidationResult{Diagnostics: diagnostics}, nil
	}
}

func validateIdentitySchema(root, schema authoringcontract.CapabilityAuthoringSchema, value any, path string, diagnostics *[]modulecapability.Diagnostic) {
	if schema.Ref != "" {
		name := strings.TrimPrefix(schema.Ref, "#/$defs/")
		resolved, found := root.Definitions[name]
		if !found || name == schema.Ref {
			addIdentityDiagnostic(diagnostics, "identity.validation.reference", path, "Identity schema reference is unresolved", map[string]string{"reference": schema.Ref})
			return
		}
		validateIdentitySchema(root, resolved, value, path, diagnostics)
		return
	}
	if len(schema.OneOf) != 0 {
		matches := 0
		for _, candidateSchema := range schema.OneOf {
			candidateDiagnostics := []modulecapability.Diagnostic{}
			validateIdentitySchema(root, candidateSchema, value, path, &candidateDiagnostics)
			if len(candidateDiagnostics) == 0 {
				matches++
			}
		}
		if matches != 1 {
			addIdentityDiagnostic(diagnostics, "identity.validation.oneof", path, "Identity value must match exactly one allowed shape", nil)
		}
		return
	}
	if !identityTypeMatches(schema.Type, value) {
		addIdentityDiagnostic(diagnostics, "identity.validation.type", path, "Identity value has the wrong type", map[string]string{"expected": schema.Type, "actual": fmt.Sprintf("%T", value)})
		return
	}
	if len(schema.Enum) != 0 && !identityEnumContains(schema.Enum, value) {
		addIdentityDiagnostic(diagnostics, "identity.validation.enum", path, "Identity value is outside the allowed set", map[string]string{"allowed": identityCanonicalString(schema.Enum), "actual": identityCanonicalString(value)})
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, required := range schema.Required {
			if _, exists := typed[required]; !exists {
				addIdentityDiagnostic(diagnostics, "identity.validation.required", path+"."+required, "Required Identity field is missing", nil)
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			property, known := schema.Properties[key]
			if !known {
				if schema.AdditionalProperties != nil && !*schema.AdditionalProperties {
					addIdentityDiagnostic(diagnostics, "identity.validation.unknown", path+"."+key, "Unknown Identity field", nil)
				}
				continue
			}
			validateIdentitySchema(root, property, typed[key], path+"."+key, diagnostics)
		}
	case []any:
		if schema.MinItems != nil && len(typed) < *schema.MinItems || schema.MaxItems != nil && len(typed) > *schema.MaxItems {
			addIdentityDiagnostic(diagnostics, "identity.validation.items", path, "Identity array length is outside the allowed range", map[string]string{"actual": strconv.Itoa(len(typed))})
		}
		if schema.Items != nil {
			for index, item := range typed {
				validateIdentitySchema(root, *schema.Items, item, fmt.Sprintf("%s[%d]", path, index), diagnostics)
			}
		}
	case string:
		length := utf8.RuneCountInString(typed)
		if schema.MinLength != nil && length < *schema.MinLength || schema.MaxLength != nil && length > *schema.MaxLength {
			addIdentityDiagnostic(diagnostics, "identity.validation.length", path, "Identity string length is outside the allowed range", map[string]string{"actual": strconv.Itoa(length)})
		}
		if schema.Format == "email" {
			if address, err := mail.ParseAddress(typed); err != nil || !strings.EqualFold(address.Address, typed) {
				addIdentityDiagnostic(diagnostics, "identity.validation.format", path, "Identity value must be an email address", map[string]string{"expected": "email"})
			}
		} else if schema.Format == "date-time" {
			if _, err := time.Parse(time.RFC3339, typed); err != nil {
				addIdentityDiagnostic(diagnostics, "identity.validation.format", path, "Identity value must be an RFC3339 date-time", map[string]string{"expected": time.RFC3339})
			}
		}
	case json.Number:
		value, err := typed.Float64()
		if err == nil && (schema.Minimum != nil && value < *schema.Minimum || schema.Maximum != nil && value > *schema.Maximum) {
			addIdentityDiagnostic(diagnostics, "identity.validation.range", path, "Identity number is outside the allowed range", map[string]string{"actual": typed.String()})
		}
	}
}

func identityTypeMatches(expected string, value any) bool {
	if expected == "" {
		return true
	}
	switch expected {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseInt(number.String(), 10, 64)
		return err == nil
	case "number":
		_, ok := value.(json.Number)
		return ok
	default:
		return true
	}
}

func identityEnumContains(values []any, actual any) bool {
	actualValue := identityCanonicalString(actual)
	for _, value := range values {
		if identityCanonicalString(value) == actualValue {
			return true
		}
	}
	return false
}

func identityCanonicalString(value any) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}

func addIdentityDiagnostic(values *[]modulecapability.Diagnostic, rule, path, message string, params map[string]string) {
	*values = append(*values, modulecapability.Diagnostic{Owner: "identity", RuleKey: rule, Severity: modulecapability.SeverityError, FieldPath: path, Message: message, Params: params})
}
