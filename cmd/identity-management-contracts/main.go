package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	auditmodule "github.com/domainry/domainry-audit/module"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

const identityAdminPagePermissionContractVersion = "identity-admin-page-permissions-v1"

type identityAdminPagePermission struct {
	Route         string `json:"route"`
	ActionKey     string `json:"action_key"`
	PermissionKey string `json:"permission_key"`
	SourceOwner   string `json:"source_owner"`
}

type identityAdminPagePermissionContract struct {
	ContractVersion string                        `json:"contract_version"`
	Pages           []identityAdminPagePermission `json:"pages"`
}

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
	builtinRegistry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		return fmt.Errorf("build Identity authoring Action registry: %w", err)
	}
	authoringProjection, err := builtinRegistry.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		return fmt.Errorf("project Identity authoring contracts: %w", err)
	}
	authoringByKey := make(map[string]authoringcontract.CapabilityAuthoringDefinition, len(authoringProjection.Domain().Capabilities))
	for _, definition := range authoringProjection.Domain().Capabilities {
		authoringByKey[definition.Key] = definition
	}
	contracts := map[string]authoringcontract.CapabilityAuthoringDefinition{
		"identity-user-authoring-contract.json":              authoringByKey["identity.user"],
		"identity-organization-unit-authoring-contract.json": authoringByKey["identity.organization_unit"],
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
	actions := identityapplication.IdentityBuiltinAuthorizationActions()
	actions = append(actions, auditmodule.AuthorizationActions()...)
	registry, err := identityapplication.NewIdentityActionRegistry(actions)
	if err != nil {
		return fmt.Errorf("build Identity Admin page Action registry: %w", err)
	}
	pages := make([]identityAdminPagePermission, 0)
	for _, action := range registry.Definitions() {
		if action.Permission == nil || action.Permission.Key != action.Key {
			continue
		}
		for _, page := range action.Pages {
			pages = append(pages, identityAdminPagePermission{
				Route: page.Route, ActionKey: action.Key,
				PermissionKey: action.Permission.Key, SourceOwner: action.Permission.Owner,
			})
		}
	}
	sort.Slice(pages, func(left, right int) bool { return pages[left].Route < pages[right].Route })
	pageContract := identityAdminPagePermissionContract{ContractVersion: identityAdminPagePermissionContractVersion, Pages: pages}
	content, err := json.MarshalIndent(pageContract, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Identity Admin page permissions: %w", err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "identity-admin-page-permissions.json"), content, 0o644); err != nil {
		return fmt.Errorf("write Identity Admin page permissions: %w", err)
	}
	return nil
}
