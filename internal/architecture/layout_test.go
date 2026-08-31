package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityUsesInternalLayeredLayout(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, required := range []string{
		"cmd/identity-server",
		"internal/application/identity",
		"internal/domain/identity/model",
		"internal/domain/identity/repository",
		"internal/domain/identity/service",
		"internal/adapter/identitysdk",
		"internal/assembly/module",
		"internal/assembly/saas",
		"internal/transport/http/module",
		"internal/transport/http/saas",
		"internal/infrastructure/persistence/database/identity",
		"internal/infrastructure/persistence/database/migration",
		"internal/infrastructure/persistence/database/schema",
		"internal/infrastructure/persistence/sqlite",
		"internal/infrastructure/persistence/mysql",
		"internal/infrastructure/persistence/postgres",
		"module",
	} {
		if info, err := os.Stat(filepath.Join(root, required)); err != nil || !info.IsDir() {
			t.Errorf("required Identity boundary %q is missing", required)
		}
	}
}

func TestPublicModuleIsThinFacade(t *testing.T) {
	entries, err := os.ReadDir("../../module")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || entry.Name() == "module.go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		t.Errorf("public module package contains implementation file %q", entry.Name())
	}
}

func TestModuleUsesTaggedDependencies(t *testing.T) {
	content, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "replace ") || strings.Contains(string(content), "../domainry-") {
		t.Fatal("Identity must consume released module tags, not local directory replacements")
	}
}

func TestIdentityDoesNotReachIntoMetadataPersistence(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(content), "domainry-metadata-sdk/"+"persistence") {
			t.Errorf("Identity source %q imports the retired Metadata persistence boundary", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		"internal/application/metadata/metadata_localized_text_coverage_application_service.go",
		"internal/domain/metadata/projection/metadata_localized_text_coverage_projection.go",
		"internal/domain/metadata/service/metadata_dictionary_domain_service.go",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err == nil {
			t.Errorf("Identity duplicate Metadata implementation returned: %s", relative)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}
