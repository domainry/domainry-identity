package architecture_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityPersistenceDoesNotReintroducePlaneRuntimeOwnership(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity persistence source root")
	}
	root := filepath.Dir(filepath.Dir(sourceFile))
	forbidden := []string{
		"RuntimeStore",
		"RuntimeOperationalMetrics",
		"_runtime_rls_policies",
		"_domainry_managed_runtime_database",
		"domainry_runtime_",
		"automation_instruction_executions",
		"workflow_execution_receipts",
		"business_action_executions",
		"record_mutation_executions",
		"integration_outbox_messages",
		"transaction_boundary_intents",
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, token := range forbidden {
			if strings.Contains(string(source), token) {
				t.Errorf("Identity persistence source %s contains Plane-owned marker %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDirectoryPaginationRemainsWorkspaceKeysetOnly(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity persistence source root")
	}
	path := filepath.Join(filepath.Dir(filepath.Dir(sourceFile)), "identity", "directory", "store.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{" OFFSET ", "identityDirectoryWhere", "identityDirectoryOrder", "Placeholder(", "PageSize + 1", "PageSize+1"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Identity directory pagination reintroduced forbidden SQL pattern %q", forbidden)
		}
	}
	for _, required := range []string{"NewWorkspaceSelectBuilder", ".FirstPage(", ".NextPage(", "pagination.Boundary", ".FetchLimit()"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Identity directory pagination lost required keyset boundary %q", required)
		}
	}
}

func TestPersistenceDoesNotBranchOnDatabaseEngine(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity persistence source root")
	}
	root := filepath.Dir(filepath.Dir(sourceFile))
	forbidden := []string{
		"driver ==", "driver !=", "dialect ==", "dialect !=",
		"switch driver", "switch dialect", "switch s.driver", "switch s.dialect",
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := strings.ToLower(string(source))
		for _, pattern := range forbidden {
			if strings.Contains(text, pattern) {
				t.Errorf("Identity persistence source %s branches on database engine with %q", path, pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBusinessPersistenceDoesNotOwnSchemaDDL(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity persistence source root")
	}
	root := filepath.Join(filepath.Dir(filepath.Dir(sourceFile)), "identity")
	forbidden := []string{"NewCreateTableBuilder", "NewAddColumnBuilder", "NewDropColumnBuilder", "NewRenameColumnBuilder", "NewCreateIndexBuilder"}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, token := range forbidden {
			if strings.Contains(string(source), token) {
				t.Errorf("Identity business persistence source %s owns schema DDL %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
