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

func TestDomainPackagesDoNotDependOnOuterLayers(t *testing.T) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve domain boundary test path")
	}
	domainRoot := filepath.Dir(sourceFile)
	forbidden := []string{
		"github.com/domainry/domainry-identity/internal/adapter",
		"github.com/domainry/domainry-identity/internal/application",
		"github.com/domainry/domainry-identity/internal/assembly",
		"github.com/domainry/domainry-identity/internal/infrastructure",
		"github.com/domainry/domainry-identity/internal/platform",
		"github.com/domainry/domainry-identity/internal/transport",
	}
	err := filepath.WalkDir(domainRoot, func(path string, entry fs.DirEntry, walkErr error) error {
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
					t.Errorf("domain package %s imports outer layer %s", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
