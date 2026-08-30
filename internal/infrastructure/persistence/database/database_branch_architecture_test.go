package database_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestDatabaseTypeBranchesStayInsideConcreteEngineProfiles(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", ".."))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		normalized := filepath.ToSlash(path)
		if strings.Contains(normalized, "/persistence/sqlite/") || strings.Contains(normalized, "/persistence/mysql/") || strings.Contains(normalized, "/persistence/postgres/") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			var expression ast.Node
			switch value := node.(type) {
			case *ast.IfStmt:
				expression = value.Cond
			case *ast.SwitchStmt:
				expression = value.Tag
			case *ast.CaseClause:
				for _, item := range value.List {
					if containsConcreteDatabase(item) {
						t.Errorf("database-type branch escaped Engine/Profile boundary: %s", path)
					}
				}
				return true
			default:
				return true
			}
			if containsConcreteDatabase(expression) {
				t.Errorf("database-type branch escaped Engine/Profile boundary: %s", path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func containsConcreteDatabase(node ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(value ast.Node) bool {
		switch typed := value.(type) {
		case *ast.BasicLit:
			if typed.Kind == token.STRING {
				text, _ := strconv.Unquote(typed.Value)
				found = isDatabaseName(text)
			}
		case *ast.Ident:
			found = found || isDatabaseName(typed.Name)
		}
		return !found
	})
	return found
}

func isDatabaseName(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sqlite", "sqlite3", "mysql", "postgres", "postgresql", "pgx":
		return true
	default:
		return false
	}
}
