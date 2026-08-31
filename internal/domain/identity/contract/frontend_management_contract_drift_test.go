package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
)

func TestFrontendManagementAuthoringContractsMatchIdentityOwner(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..", "frontend", "packages", "management-contract", "src", "generated")
	contracts := map[string]authoringcontract.CapabilityAuthoringDefinition{
		"identity-user-authoring-contract.json":                 IdentityUserAuthoringCapability(),
		"identity-workforce-profile-authoring-contract.json":    IdentityWorkforceProfileAuthoringCapability(),
		"identity-workforce-assignment-authoring-contract.json": IdentityWorkforceAssignmentAuthoringCapability(),
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
