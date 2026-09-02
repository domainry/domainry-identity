package identitysdkadapter

import (
	"encoding/json"
	"testing"

	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulecapability/contracttest"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func TestIdentityCapabilityBindingTracksOwnerAuthoringDomain(t *testing.T) {
	binding, err := NewCapabilityBinding()
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
	totalOperations, totalScopes := 0, 0
	for _, category := range summary.Categories {
		totalOperations += category.OperationCount
		totalScopes += len(category.ValidationScopes)
		if category.OperationCount > 20 {
			t.Fatalf("category %q exceeds the bounded 20-operation batch: %d", category.Key, category.OperationCount)
		}
	}
	if len(summary.Categories) != 3 || totalOperations != len(operations) || totalScopes != 1 {
		t.Fatalf("summary=%+v owner capabilities=%d routes=%d", summary.Categories, len(domain.Capabilities), len(operations))
	}
}

func TestIdentityCapabilityModuleAndHTTPParity(t *testing.T) {
	binding, err := NewCapabilityBinding()
	if err != nil {
		t.Fatal(err)
	}
	summary, err := binding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	contracttest.VerifyModuleRemoteParity(t, binding,
		contracttest.ValidationCase{Name: "valid role", Request: identityValidationRequest(summary, `{"key":"sales","name":"Sales","permissions":[],"record_scope":"all_records"}`)},
		contracttest.ValidationCase{Name: "invalid role", Request: identityValidationRequest(summary, `{"key":"other","name":"Sales","permissions":[],"record_scope":"invalid","unknown":true}`)},
	)
}

func TestIdentityCapabilityValidatorUsesOwnerSchema(t *testing.T) {
	binding, err := NewCapabilityBinding()
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := binding.CapabilitySummary(t.Context())
	result, err := binding.ValidateCapabilityCandidate(t.Context(), identityValidationRequest(summary, `{"key":"other","name":"Sales","permissions":[],"record_scope":"all_records","unknown":true}`))
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

func identityValidationRequest(summary modulecapability.ModuleSummary, candidate string) modulecapability.ValidationRequest {
	return modulecapability.ValidationRequest{
		ContractVersion: modulecapability.ValidationContractVersion,
		ModuleKey:       "identity",
		CategoryKey:     identityCapabilityCategory("identity.role"),
		ContractSHA256:  summary.Identity.ContractSHA256,
		Kind:            "identity.role",
		Candidate:       modulecapability.AuthoringFragment{Collection: "roles", Key: "sales", Value: json.RawMessage(candidate)},
	}
}
