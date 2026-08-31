package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func main() {
	outputDir := flag.String("output-dir", filepath.Join("frontend", "packages", "management-contract", "src", "generated"), "directory for generated Identity management authoring contracts")
	flag.Parse()
	if err := generate(*outputDir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	contracts := map[string]authoringcontract.CapabilityAuthoringDefinition{
		"identity-user-authoring-contract.json":                 identitycontract.IdentityUserAuthoringCapability(),
		"identity-workforce-profile-authoring-contract.json":    identitycontract.IdentityWorkforceProfileAuthoringCapability(),
		"identity-workforce-assignment-authoring-contract.json": identitycontract.IdentityWorkforceAssignmentAuthoringCapability(),
	}
	for name, definition := range contracts {
		content, err := json.MarshalIndent(definition, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		content = append(content, '\n')
		if err := os.WriteFile(filepath.Join(outputDir, name), content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
