package capability

import (
	"encoding/json"
	"testing"

	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulecapability/contracttest"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func TestIdentityCapabilityBindingTracksOwnerAuthoringDomain(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	contracttest.VerifyBinding(t, binding)
	summary, err := binding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		t.Fatal(err)
	}
	domain := projection.Domain()
	operations := map[string]bool{}
	for _, capability := range domain.Capabilities {
		for _, route := range capability.ConfigurationRoutes {
			operations[route] = true
		}
	}
	nonHTTPCapabilities := map[string]bool{}
	for _, definition := range registry.Definitions() {
		if len(definition.NonHTTP) != 0 {
			nonHTTPCapabilities[definition.CapabilityKey] = true
		}
	}
	totalOperations, totalScopes := 0, 0
	for _, category := range summary.Categories {
		totalOperations += category.OperationCount
		totalScopes += len(category.ValidationScopes)
		if category.OperationCount > 20 {
			t.Fatalf("category %q exceeds the bounded 20-operation batch: %d", category.Key, category.OperationCount)
		}
	}
	if len(summary.Categories) != 3+len(nonHTTPCapabilities) || totalOperations != len(operations) || totalScopes != 1 {
		t.Fatalf("summary=%+v owner capabilities=%d routes=%d", summary.Categories, len(domain.Capabilities), len(operations))
	}
}

func TestIdentityCapabilityBindingDisclosesNonHTTPDeliveryAndUsageActions(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := binding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provided := map[string]bool{}
	for _, key := range summary.Composition.ProvidedCapabilities {
		provided[key] = true
	}
	for capabilityKey, actionKeys := range map[string][]string{
		"identity.handler_delivery":            {"identity.handler_delivery.create", "identity.handler_delivery.update", "identity.handler_delivery.disable", "identity.handler_delivery.resolve"},
		"identity.store_organization_delivery": {"identity.store_organization_delivery.create", "identity.store_organization_delivery.rename", "identity.store_organization_delivery.disable", "identity.store_organization_delivery.resolve", "identity.store_organization_delivery.list"},
		"identity.organization_unit_delivery":  {"identity.organization_unit_delivery.create", "identity.organization_unit_delivery.resolve"},
		"identity.workspace_identity_usage":    {"identity.workspace_identity_usage.aggregate"},
	} {
		if !provided[capabilityKey] {
			t.Fatalf("provided capabilities do not contain %q: %v", capabilityKey, summary.Composition.ProvidedCapabilities)
		}
		document, err := binding.CapabilityCategory(t.Context(), capabilityKey)
		if err != nil {
			t.Fatal(err)
		}
		if document.Category.OperationCount != 0 || len(document.Projections) != len(actionKeys) {
			t.Fatalf("category %q=%+v projections=%+v", capabilityKey, document.Category, document.Projections)
		}
		seen := map[string]bool{}
		for _, projection := range document.Projections {
			if projection.Kind != "identity.non_http_action" {
				t.Fatalf("category %q projection %q has kind %q", capabilityKey, projection.Key, projection.Kind)
			}
			seen[projection.Key] = true
		}
		for _, actionKey := range actionKeys {
			if !seen[actionKey] {
				t.Fatalf("category %q does not project Action %q: %v", capabilityKey, actionKey, seen)
			}
		}
	}
}

func TestIdentityCapabilityModuleAndHTTPParity(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := binding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	contracttest.VerifyModuleRemoteParity(t, binding,
		contracttest.ValidationCase{Name: "valid role", Request: identityValidationRequest(summary, `{"key":"sales","name":"Sales","permissions":[]}`)},
		contracttest.ValidationCase{Name: "invalid role", Request: identityValidationRequest(summary, `{"key":"other","name":"Sales","permissions":[],"unknown":true}`)},
	)
}

func TestIdentityCapabilityValidatorUsesOwnerSchema(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := binding.CapabilitySummary(t.Context())
	result, err := binding.ValidateCapabilityCandidate(t.Context(), identityValidationRequest(summary, `{"key":"other","name":"Sales","permissions":[],"unknown":true}`))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, diagnostic := range result.Diagnostics {
		seen[diagnostic.RuleKey] = true
	}
	if !seen["identity.validation.source_key"] || !seen["identity.validation.unknown"] {
		t.Fatalf("diagnostics=%+v", result.Diagnostics)
	}
}

func TestIdentityCapabilityValidatorAcceptsProtectedInstallationAdministratorExtension(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := binding.CapabilitySummary(t.Context())
	result, err := binding.ValidateCapabilityCandidate(t.Context(), identityValidationRequestForKey(summary, "tenant_admin", `{
		"key":"tenant_admin",
		"name":"Installation administrator",
		"permissions":[{"permission_key":"order.read","data_scope":"all"}],
		"audience":"user",
		"assignment_mode":"system_managed",
		"risk_level":"privileged",
		"platform_role_extension":true
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Diagnostics) != 0 {
		t.Fatalf("diagnostics=%+v", result.Diagnostics)
	}
}

func TestIdentityCapabilityValidatorRejectsInvalidPlatformRoleExtensions(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := binding.CapabilitySummary(t.Context())
	for _, test := range []struct {
		name      string
		sourceKey string
		candidate string
	}{
		{name: "marker must be true", sourceKey: "tenant_admin", candidate: `{"key":"tenant_admin","name":"Installation administrator","permissions":[{"permission_key":"order.read","data_scope":"all"}],"audience":"user","assignment_mode":"system_managed","risk_level":"privileged","platform_role_extension":false}`},
		{name: "only installation administrator", sourceKey: "sales", candidate: `{"key":"sales","name":"Installation administrator","permissions":[{"permission_key":"order.read","data_scope":"all"}],"audience":"user","assignment_mode":"system_managed","risk_level":"privileged","platform_role_extension":true}`},
		{name: "identity policy is immutable", sourceKey: "tenant_admin", candidate: `{"key":"tenant_admin","name":"Project administrator","permissions":[],"audience":"user","assignment_mode":"manual","provision_to_workspaces":true,"risk_level":"privileged","permission_set_keys":["project_owned"],"platform_role_extension":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := binding.ValidateCapabilityCandidate(t.Context(), identityValidationRequestForKey(summary, test.sourceKey, test.candidate))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, diagnostic := range result.Diagnostics {
				if diagnostic.RuleKey == "identity.validation.platform_role_extension" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("diagnostics=%+v", result.Diagnostics)
			}
		})
	}
}

func identityValidationRequest(summary modulecapability.ModuleSummary, candidate string) modulecapability.ValidationRequest {
	return identityValidationRequestForKey(summary, "sales", candidate)
}

func identityValidationRequestForKey(summary modulecapability.ModuleSummary, sourceKey, candidate string) modulecapability.ValidationRequest {
	return modulecapability.ValidationRequest{
		ContractVersion: modulecapability.ValidationContractVersion,
		ModuleKey:       "identity",
		CategoryKey:     identityCapabilityCategory("identity.role"),
		ContractSHA256:  summary.Identity.ContractSHA256,
		Kind:            "identity.role",
		Candidate:       modulecapability.AuthoringFragment{Collection: "roles", Key: sourceKey, Value: json.RawMessage(candidate)},
	}
}
