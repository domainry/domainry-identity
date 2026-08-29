package architecture_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityBlackBoxTestsRemainClassified(t *testing.T) {
	identityRoot := identityPersistenceRoot(t)
	entries, err := os.ReadDir(identityRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, readErr := os.ReadFile(filepath.Join(identityRoot, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if regexp.MustCompile(`(?m)^package\s+identity_test\s*$`).Match(source) {
			t.Errorf("black-box Identity test %s belongs in identity/integrationtest", entry.Name())
		}
	}
}

func TestIdentityBusinessPersistenceUsesStructuredBuilders(t *testing.T) {
	identityRoot := identityPersistenceRoot(t)
	rawCRUD := regexp.MustCompile(`(?i)\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+[A-Za-z_]|DELETE\s+FROM)\b`)
	var violations []string
	err := filepath.WalkDir(identityRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != identityRoot && entry.Name() == "integrationtest" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if rawCRUD.Match(source) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("Identity business persistence must use ORM builders: %s", strings.Join(violations, ", "))
	}
}

func identityPersistenceRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity architecture source")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(sourceFile)), "identity")
}
