package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefinitionsCoverEveryConfigField(t *testing.T) {
	definitions := Definitions()
	if len(definitions) != reflect.TypeOf(Config{}).NumField() {
		t.Fatalf("schema drift: definitions=%d config_fields=%d", len(definitions), reflect.TypeOf(Config{}).NumField())
	}
	seen := map[string]bool{}
	for _, definition := range definitions {
		if definition.Name == "" || definition.Owner == "" || definition.Type == "" {
			t.Fatalf("incomplete definition: %#v", definition)
		}
		if seen[definition.Name] {
			t.Fatalf("duplicate external config name %s", definition.Name)
		}
		seen[definition.Name] = true
	}
}

func TestLoadPermissionOwnerListsThroughConfigContract(t *testing.T) {
	const name = "IDENTITY_APPLICATION_PERMISSION_OWNERS"
	const raw = " workspace/app = application:app | module:agent , workspace/other=module:report "
	t.Setenv(name, raw)
	want := FromEnv().IdentityApplicationPermissionOwners
	loaded, _, err := LoadContract(Source{Name: "environment", Values: map[string]string{name: raw}})
	if err != nil || !reflect.DeepEqual(loaded.IdentityApplicationPermissionOwners, want) {
		t.Fatalf("permission owner list differs from environment parser: %v %v", loaded.IdentityApplicationPermissionOwners, err)
	}
	loaded, snapshot, err := LoadContract(
		Source{Name: "file", Priority: 100, Values: map[string]string{name: raw}},
		Source{Name: "operator", Priority: 300, Values: map[string]string{name: "workspace/app=module:report"}},
	)
	if err != nil || !reflect.DeepEqual(loaded.IdentityApplicationPermissionOwners, map[string][]string{"workspace/app": {"module:report"}}) || snapshot.Entries[name].Source != "operator" {
		t.Fatalf("permission owner override merged stale grants: %v %v", loaded.IdentityApplicationPermissionOwners, err)
	}
	loaded, _, err = LoadContract(Source{Name: "operator", Values: map[string]string{name: ""}})
	if err != nil || len(loaded.IdentityApplicationPermissionOwners) != 0 {
		t.Fatalf("empty owner configuration retained grants: %v", err)
	}
}

func TestFromEnvUsesLongLivedAuthSessionDefaults(t *testing.T) {
	t.Setenv("AUTH_ACCESS_TTL", "")
	t.Setenv("AUTH_REFRESH_TTL", "")

	cfg := FromEnv()
	if cfg.AuthAccessTTL != 24*time.Hour {
		t.Fatalf("access TTL=%v want=%v", cfg.AuthAccessTTL, 24*time.Hour)
	}
	if cfg.AuthRefreshTTL != 30*24*time.Hour {
		t.Fatalf("refresh TTL=%v want=%v", cfg.AuthRefreshTTL, 30*24*time.Hour)
	}
}

func TestLoadWithProjectFileUsesDefaultProjectOperatorPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{"APP_LOCALE":"zh-CN","PORT":":4567"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNTIME_CONFIG_FILE", "")
	t.Setenv("RUNTIME_REMOTE_CONFIG_FILE", "")
	t.Setenv("PORT", ":5678")
	cfg, snapshot, err := LoadWithProjectFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppLocale != "zh-CN" || cfg.Port != ":5678" {
		t.Fatalf("config=%+v", cfg)
	}
	if snapshot.Entries["APP_LOCALE"].Source != "project-configuration" || snapshot.Entries["PORT"].Source != "environment" {
		t.Fatalf("provenance=%+v", snapshot.Entries)
	}
	if _, defaults, err := LoadWithProjectFile(filepath.Join(t.TempDir(), "absent.json")); err != nil || defaults.Entries["APP_LOCALE"].Source != "default" {
		t.Fatalf("absent project extension snapshot=%+v err=%v", defaults, err)
	}
}

func TestLoadWithProjectFileRejectsUnknownSecretAndSymlink(t *testing.T) {
	for name, document := range map[string]struct {
		document string
		expected string
	}{
		"unknown": {`{"NOT_A_RUNTIME_SETTING":"x"}`, "unknown configuration"},
		"secret":  {`{"AUTH_JWT_SECRET":"must-not-live-in-git"}`, "forbidden in Git-owned"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, []byte(document.document), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadWithProjectFile(path); err == nil || !strings.Contains(err.Error(), document.expected) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	target := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWithProjectFile(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error=%v", err)
	}
}

func TestOptionalProjectConfigFileRejectsUnreadableMalformedAndTrailingDocuments(t *testing.T) {
	for name, content := range map[string]string{
		"malformed": `{`,
		"trailing":  `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readOptionalProjectConfigFile(path); err == nil {
				t.Fatalf("%s project configuration was accepted", name)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, _, err := readOptionalProjectConfigFile(path); err == nil || !strings.Contains(err.Error(), "read project configuration") {
		t.Fatalf("unreadable project configuration error=%v", err)
	}
}

func TestLoadContractUsesExplicitPriorityAndProvenance(t *testing.T) {
	cfg, snapshot, err := LoadContract(
		Source{Name: "file", Version: "file-7", Priority: 100, Values: map[string]string{"PORT": "8082", "APP_LOCALE": "zh-CN"}},
		Source{Name: "environment", Version: "deploy-4", Priority: 300, Values: map[string]string{"PORT": "9090"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "9090" || cfg.AppLocale != "zh-CN" {
		t.Fatalf("priority not applied: %#v", cfg)
	}
	if snapshot.Entries["PORT"].Source != "environment" || snapshot.Entries["PORT"].Version != "deploy-4" {
		t.Fatalf("provenance missing: %#v", snapshot.Entries["PORT"])
	}
	if snapshot.Revision == "" {
		t.Fatal("snapshot revision missing")
	}
}

func TestLoadContractRejectsTyposAndInvalidCombinations(t *testing.T) {
	if _, _, err := LoadContract(Source{Name: "environment", Values: map[string]string{"AUTH_JWT_SECRT": "typo"}}); err == nil {
		t.Fatal("unknown configuration was silently accepted")
	}
	if _, _, err := LoadContract(Source{Name: "environment", Values: map[string]string{"AUTH_ACCESS_TTL": "2h", "AUTH_REFRESH_TTL": "1h"}}); err == nil {
		t.Fatal("invalid TTL combination was accepted")
	}
	if _, _, err := LoadContract(Source{Name: "environment", Values: map[string]string{"HTTP_READ_TIMEOUT": "not-a-duration"}}); err == nil {
		t.Fatal("invalid duration silently fell back")
	}
}

func TestProductionSecurityRejectsJWTEncryptionFallback(t *testing.T) {
	cfg := Config{Environment: "production", AuthJWTSecret: "shared", AuthDefaultPassword: "StrongPassword!", IdentityDataSecretKey: "shared", IdentityDataActiveKeyID: "key-1", CORSAllowedOrigins: []string{"https://admin.example.com"}, AuthPasswordMinLength: 12}
	if err := cfg.ValidateSecurity(); err == nil {
		t.Fatal("production accepted JWT secret as integration encryption key")
	}
}

func TestLoadRejectsMisspelledManagedEnvironmentVariable(t *testing.T) {
	t.Setenv("CONFIG_UNKNOWN_POLICY", "error")
	t.Setenv("AUTH_JWT_SECRT", "typo")
	if _, _, err := Load(); err == nil {
		t.Fatal("misspelled managed environment variable was ignored")
	}
}

func TestProductionSecurityHardGates(t *testing.T) {
	valid := Config{Environment: "production", AuthJWTSecret: "jwt", AuthJWTActiveKID: "jwt-1", AuthDefaultPassword: "StrongPassword!", IdentityDataSecretKey: "integration", IdentityDataActiveKeyID: "data-1", CORSAllowedOrigins: []string{"https://admin.example.com"}, AuthPasswordMinLength: 12}
	setValidProductionListeners(&valid)
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"default JWT", func(cfg *Config) { cfg.AuthJWTSecret = DevJWTSecret }},
		{"default integration key", func(cfg *Config) { cfg.IdentityDataSecretKey = DevIdentityDataSecret }},
		{"open CORS", func(cfg *Config) { cfg.CORSAllowedOrigins = []string{"*"} }},
		{"dev headers", func(cfg *Config) { cfg.AuthAllowDevHeaders = true }},
		{"weak password policy", func(cfg *Config) { cfg.AuthPasswordMinLength = 7 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.ValidateSecurity(); err == nil {
				t.Fatalf("production accepted %s", test.name)
			}
		})
	}
}
