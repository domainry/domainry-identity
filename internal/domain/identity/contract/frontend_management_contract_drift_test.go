package contract_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func TestFrontendManagementAuthoringContractsMatchIdentityOwner(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..", "frontend", "packages", "management-contract", "src", "generated")
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := registry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]authoringcontract.CapabilityAuthoringDefinition{}
	for _, definition := range projection.Domain().Capabilities {
		byKey[definition.Key] = definition
	}
	contracts := map[string]authoringcontract.CapabilityAuthoringDefinition{
		"identity-user-authoring-contract.json":              byKey["identity.user"],
		"identity-organization-unit-authoring-contract.json": byKey["identity.organization_unit"],
	}
	for name, definition := range contracts {
		name, definition := name, definition
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			expected, err := json.MarshalIndent(definition, "", "  ")
			if err != nil {
				t.Fatalf("marshal Identity-owned authoring contract: %v", err)
			}
			expected = append(expected, '\n')
			path := filepath.Join(root, name)
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read frontend management contract %s: %v", path, err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("frontend management contract %s drifted from the Identity owner; regenerate it from the matching Identity authoring capability", name)
			}
		})
	}
}
