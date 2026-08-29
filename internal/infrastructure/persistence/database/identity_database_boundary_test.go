package database_test

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
	root := filepath.Dir(sourceFile)
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
