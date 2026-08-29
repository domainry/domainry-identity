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

func TestIdentityWorkforceLifecycleRootFilesRemainFacades(t *testing.T) {
	identityRoot := identityPersistenceRoot(t)
	files := []string{
		"identity_workforce_lifecycle_store.go",
		"identity_workforce_onboarding_store.go",
		"identity_workforce_termination_store.go",
	}
	for _, name := range files {
		source, err := os.ReadFile(filepath.Join(identityRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{"ormbuilder", ".BeginTx(", ".ExecContext(", ".QueryRowContext("} {
			if strings.Contains(text, forbidden) {
				t.Errorf("Identity workforce facade %s owns persistence implementation %q", name, forbidden)
			}
		}
	}
}

func TestIdentityAccessReviewRootFileRemainsFacade(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(identityPersistenceRoot(t), "identity_access_review_store.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{"ormbuilder", ".BeginTx(", ".ExecContext(", ".QueryRowContext("} {
		if strings.Contains(text, forbidden) {
			t.Errorf("Identity access review facade owns persistence implementation %q", forbidden)
		}
	}
	if !strings.Contains(text, "accessreviewpersistence.New") {
		t.Error("Identity access review facade lost classified owner delegation")
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
