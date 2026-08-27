package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigHelperAndSecurityRemainingConditions(t *testing.T) {
	if mode := (Config{DatabaseMigrationMode: " APPLY "}).EffectiveDatabaseMigrationMode(); mode != "apply" {
		t.Fatalf("explicit migration mode=%q", mode)
	}
	if mode := (Config{Environment: "production"}).EffectiveDatabaseMigrationMode(); mode != "verify" {
		t.Fatalf("production migration mode=%q", mode)
	}
	secure := Config{
		Environment: "production", AuthJWTSecret: "jwt-secret", AuthJWTActiveKID: "jwt-1",
		AuthDefaultPassword: "StrongPassword!", AuthPasswordMinLength: 12,
		IdentityDataSecretKey: "integration-secret", IdentityDataActiveKeyID: "data-1",
		CORSAllowedOrigins: []string{"https://admin.example.com"},
	}
	setValidProductionListeners(&secure)
	sharedSecret := secure
	sharedSecret.IdentityDataSecretKey = sharedSecret.AuthJWTSecret
	if err := sharedSecret.ValidateSecurity(); err == nil || !strings.Contains(err.Error(), "IDENTITY_DATA_SECRET_KEY") {
		t.Fatalf("shared secret error=%v", err)
	}
	secureTelemetry := secure
	secureTelemetry.TelemetryEndpoint = "https://otel.example.com"
	if err := secureTelemetry.ValidateSecurity(); err != nil {
		t.Fatalf("secure telemetry=%v", err)
	}

	providers := []map[string]any{{"key": "blank-priority", "priority": "p2", "priority_by_market": map[string]string{"jp": " "}}}
	if got := providersForMarket(providers, "jp"); got[0]["priority"] != "p2" {
		t.Fatalf("blank market priority=%v", got)
	}

	t.Setenv("CONFIG_EDGE_DURATION_ZERO", "-1")
	if got := durationEnv("CONFIG_EDGE_DURATION_ZERO", time.Minute); got != time.Minute {
		t.Fatalf("zero duration=%v", got)
	}
	t.Setenv("CONFIG_EDGE_INT_NEGATIVE", "-1")
	if got := intEnv("CONFIG_EDGE_INT_NEGATIVE", 7); got != 7 {
		t.Fatalf("negative int=%d", got)
	}
	t.Setenv("CONFIG_EDGE_KEY_VALUE", " =ignored,valid=value")
	if got := keyValueEnv("CONFIG_EDGE_KEY_VALUE", ""); len(got) != 1 || got["valid"] != "value" {
		t.Fatalf("key values=%v", got)
	}
	if err := validateProductionRedirectURL("REDIRECT", "https:/callback"); err == nil {
		t.Fatal("hostless HTTPS redirect accepted")
	}
}

func TestConfigLoadWithoutUnknownsAndSourceStatFailure(t *testing.T) {
	known := map[string]bool{}
	for _, definition := range Definitions() {
		known[definition.Name] = true
	}
	type savedEnvironment struct {
		name  string
		value string
	}
	saved := []savedEnvironment{}
	for _, item := range os.Environ() {
		name, value, _ := strings.Cut(item, "=")
		base := strings.TrimSuffix(name, "_FILE")
		if managedConfigName(name) && !known[base] {
			saved = append(saved, savedEnvironment{name: name, value: value})
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		for _, item := range saved {
			_ = os.Setenv(item.name, item.value)
		}
	})
	if _, snapshot, err := Load(); err != nil || len(snapshot.Warnings) != 0 {
		t.Fatalf("clean load warnings=%v err=%v", snapshot.Warnings, err)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"PORT":"9090"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_EDGE_STAT", path)
	previousStat := configSourceStat
	configSourceStat = func(string) (os.FileInfo, error) { return nil, errors.New("stat failed") }
	t.Cleanup(func() { configSourceStat = previousStat })
	if _, _, err := readConfigSourceFile("CONFIG_EDGE_STAT"); err == nil || !strings.Contains(err.Error(), "stat CONFIG_EDGE_STAT") {
		t.Fatalf("stat error=%v", err)
	}
}

func TestOptionalProjectConfigFileStatAndTypeFailures(t *testing.T) {
	previous := optionalProjectConfigLstat
	optionalProjectConfigLstat = func(string) (os.FileInfo, error) { return nil, errors.New("lstat failed") }
	t.Cleanup(func() { optionalProjectConfigLstat = previous })
	if _, _, err := readOptionalProjectConfigFile("config.json"); err == nil {
		t.Fatal("lstat failure was ignored")
	}
	optionalProjectConfigLstat = os.Lstat
	if _, _, err := readOptionalProjectConfigFile(t.TempDir()); err == nil {
		t.Fatal("directory project config was accepted")
	}
}

func TestConfigValidateEveryShortCircuitOperand(t *testing.T) {
	valid, _, err := LoadContract()
	if err != nil {
		t.Fatal(err)
	}
	valid.Environment = "development"
	for _, host := range []string{"localhost", "127.0.0.1"} {
		hostConfig := valid
		hostConfig.HTTPBindHost = host
		if err := hostConfig.Validate(); err != nil {
			t.Fatalf("valid bind host %q: %v", host, err)
		}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"read header timeout", func(c *Config) { c.HTTPReadHeaderTimeout = 0 }},
		{"write timeout", func(c *Config) { c.HTTPWriteTimeout = 0 }},
		{"idle timeout", func(c *Config) { c.HTTPIdleTimeout = 0 }},
		{"shutdown timeout", func(c *Config) { c.HTTPShutdownTimeout = 0 }},
		{"access ttl", func(c *Config) { c.AuthAccessTTL = 0 }},
		{"port syntax", func(c *Config) { c.Port = "not-a-port" }},
		{"port zero", func(c *Config) { c.Port = "0" }},
		{"body high", func(c *Config) { c.HTTPMaxJSONBodyBytes = (64 << 20) + 1 }},
		{"telemetry ratio negative", func(c *Config) { c.TelemetrySampleRatio = -0.1 }},
		{"database open zero", func(c *Config) { c.DatabaseMaxOpenConns = 0 }},
		{"database idle negative", func(c *Config) { c.DatabaseMaxIdleConns = -1 }},
		{"database lifetime zero", func(c *Config) { c.DatabaseConnMaxLifetime = 0 }},
		{"database idle time zero", func(c *Config) { c.DatabaseConnMaxIdleTime = 0 }},
		{"database connect zero", func(c *Config) { c.DatabaseConnectTimeout = 0 }},
		{"database statement zero", func(c *Config) { c.DatabaseStatementTimeout = 0 }},
		{"manifest path empty", func(c *Config) { c.ManifestPath = " " }},
		{"migration path empty", func(c *Config) { c.MigrationDir = " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("invalid config accepted: %+v", cfg)
			}
		})
	}
}

func TestConfigUnknownProductionPolicyCondition(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_ALLOW_DEV_HEADERS", "false")
	t.Setenv("AUTH_JWT_SECRET", "production-jwt-secret")
	t.Setenv("AUTH_JWT_ACTIVE_KID", "jwt-1")
	t.Setenv("AUTH_DEFAULT_PASSWORD", "StrongProductionPassword!")
	t.Setenv("AUTH_PASSWORD_MIN_LENGTH", "12")
	t.Setenv("IDENTITY_DATA_SECRET_KEY", "production-integration-secret")
	t.Setenv("IDENTITY_DATA_ACTIVE_KEY_ID", "data-1")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://admin.example.com")
	t.Setenv("HTTP_PUBLIC_ADDR", "0.0.0.0:8081")
	t.Setenv("HTTP_TENANT_ADMIN_ADDR", "127.0.0.1:8082")
	t.Setenv("HTTP_OPS_ADDR", "127.0.0.1:8083")
	t.Setenv("IDENTITY_OPERATIONS_ACCESS_TOKEN", "operations-access-token")
	t.Setenv("RUNTIME_UNKNOWN_PRODUCTION_EDGE", "value")
	if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "RUNTIME_UNKNOWN_PRODUCTION_EDGE") {
		t.Fatalf("unknown production configuration error=%v", err)
	}
}
