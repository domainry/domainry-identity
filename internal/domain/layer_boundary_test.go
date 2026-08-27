package domain_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestApplicationPackagesDoNotDependOnOuterAdapters(t *testing.T) {
	internalRoot := identityInternalRoot(t)
	assertProductionImportsExclude(t, filepath.Join(internalRoot, "application"), []string{
		"github.com/domainry/domainry-identity/internal/adapter",
		"github.com/domainry/domainry-identity/internal/assembly",
		"github.com/domainry/domainry-identity/internal/infrastructure",
		"github.com/domainry/domainry-identity/internal/transport",
	})
}

func TestIdentitySDKAdapterDoesNotChooseInfrastructure(t *testing.T) {
	internalRoot := identityInternalRoot(t)
	assertProductionImportsExclude(t, filepath.Join(internalRoot, "adapter", "identitysdk"), []string{
		"github.com/domainry/domainry-identity/internal/assembly",
		"github.com/domainry/domainry-identity/internal/infrastructure",
		"github.com/domainry/domainry-identity/internal/transport",
	})
}

func identityInternalRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Identity layer boundary test path")
	}
	return filepath.Dir(filepath.Dir(sourceFile))
}

func assertProductionImportsExclude(t *testing.T, root string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, declaration := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(declaration.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			for _, prefix := range forbidden {
				if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
					t.Errorf("layer file %s imports forbidden outer package %s", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
