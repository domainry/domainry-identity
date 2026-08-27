package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidateSecurityRemainingProductionGates(t *testing.T) {
	valid := Config{
		Environment: "production", AuthJWTSecret: "jwt-secret", AuthJWTActiveKID: "jwt-1",
		AuthDefaultPassword: "StrongPassword!", AuthPasswordMinLength: 12,
		IdentityDataSecretKey: "integration-secret", IdentityDataActiveKeyID: "data-1",
		CORSAllowedOrigins: []string{"https://admin.example.com"},
	}
	setValidProductionListeners(&valid)
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing jwt", mutate: func(c *Config) { c.AuthJWTSecret = " " }, want: "AUTH_JWT_SECRET"},
		{name: "missing jwt kid", mutate: func(c *Config) { c.AuthJWTActiveKID = " " }, want: "AUTH_JWT_ACTIVE_KID"},
		{name: "missing password", mutate: func(c *Config) { c.AuthDefaultPassword = " " }, want: "AUTH_DEFAULT_PASSWORD"},
		{name: "default password", mutate: func(c *Config) { c.AuthDefaultPassword = DevDefaultAdminPassword }, want: "AUTH_DEFAULT_PASSWORD"},
		{name: "postgres without rls", mutate: func(c *Config) { c.DatabaseDriver = "postgres"; c.DatabaseRLSEnabled = false }, want: "DATABASE_RLS_ENABLED"},
		{name: "missing integration key", mutate: func(c *Config) { c.IdentityDataSecretKey = " " }, want: "IDENTITY_DATA_SECRET_KEY"},
		{name: "missing integration kid", mutate: func(c *Config) { c.IdentityDataActiveKeyID = " " }, want: "IDENTITY_DATA_ACTIVE_KEY_ID"},
		{name: "missing operations token", mutate: func(c *Config) { c.IdentityOperationsAccessToken = " " }, want: "IDENTITY_OPERATIONS_ACCESS_TOKEN"},
		{name: "insecure telemetry", mutate: func(c *Config) { c.TelemetryEndpoint = "https://otel.example.com"; c.TelemetryInsecure = true }, want: "TELEMETRY_INSECURE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.ValidateSecurity(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want=%q", err, test.want)
			}
		})
	}
	valid.AuthPasswordMinLength = 0
	if err := valid.ValidateSecurity(); err != nil {
		t.Fatalf("default minimum password length: %v", err)
	}
	valid.Environment = "test"
	valid.AuthAllowDevHeaders = true
	if err := valid.ValidateSecurity(); err != nil {
		t.Fatalf("non-production security validation: %v", err)
	}
}

func TestProductionApplicationServiceCredentialsAreStrongScopedSecrets(t *testing.T) {
	valid := Config{
		Environment: "production", AuthJWTSecret: "jwt-secret", AuthJWTActiveKID: "jwt-1",
		AuthDefaultPassword: "StrongPassword!", AuthPasswordMinLength: 12,
		IdentityDataSecretKey: "integration-secret", IdentityDataActiveKeyID: "data-1",
		IdentityOperationsAccessToken: "operations-access-token",
		IdentityApplicationServiceCredentials: map[string]string{
			"default/orders-runtime": "orders-runtime-credential-with-32-characters",
		},
	}
	setValidProductionListeners(&valid)
	if err := valid.ValidateSecurity(); err != nil {
		t.Fatalf("valid application service credential: %v", err)
	}
	for name, credentials := range map[string]map[string]string{
		"weak":       {"default/orders-runtime": "short"},
		"reused":     {"default/orders-runtime": "shared-runtime-credential-with-32-chars", "default/notify-runtime": "shared-runtime-credential-with-32-chars"},
		"operations": {"default/orders-runtime": "operations-access-token"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			cfg.IdentityApplicationServiceCredentials = credentials
			if err := cfg.ValidateSecurity(); err == nil || !strings.Contains(err.Error(), "IDENTITY_APPLICATION_SERVICE_CREDENTIALS") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestApplicationServiceCredentialsLoadAsRedactedKeyMap(t *testing.T) {
	t.Setenv("IDENTITY_APPLICATION_SERVICE_CREDENTIALS", "default/orders-runtime=orders-secret,default/notify-runtime=notify-secret")
	cfg := FromEnv()
	if got := cfg.IdentityApplicationServiceCredentials["default/orders-runtime"]; got != "orders-secret" {
		t.Fatalf("orders credential=%q", got)
	}
	definition, ok := definitionByName(Definitions(), "IDENTITY_APPLICATION_SERVICE_CREDENTIALS")
	if !ok || definition.Type != TypeKeyMap || !definition.Secret || definition.Default != "[REDACTED]" {
		t.Fatalf("credential definition=%+v found=%v", definition, ok)
	}
}

func TestProductionSaaSDeploymentRequiresAnApplicationCredential(t *testing.T) {
	if err := (Config{Environment: "production"}).ValidateSaaSDeployment(); err == nil || !strings.Contains(err.Error(), "IDENTITY_APPLICATION_SERVICE_CREDENTIALS") {
		t.Fatalf("missing SaaS credential error=%v", err)
	}
	if err := (Config{Environment: "production", IdentityApplicationServiceCredentials: map[string]string{"default/orders-runtime": "secret"}}).ValidateSaaSDeployment(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Environment: "development"}).ValidateSaaSDeployment(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthProviderMarketOrderingAndClassification(t *testing.T) {
	providers := []map[string]any{
		{"key": "fallback", "label": "Zulu", "priority": "unknown"},
		{"key": "regional", "label": "Alpha", "priority": "p2", "markets": []string{"br"}, "priority_by_market": map[string]string{"jp": "p0"}},
		{"key": "global", "label": "Beta", "priority": "p1", "markets": []string{"global"}},
		{"key": "native", "label": "Gamma", "priority": "p0", "markets": []string{"jp"}},
	}
	ordered := providersForMarket(providers, " ")
	if got := []string{ordered[0]["key"].(string), ordered[1]["key"].(string), ordered[2]["key"].(string), ordered[3]["key"].(string)}; !reflect.DeepEqual(got, []string{"regional", "native", "global", "fallback"}) {
		t.Fatalf("order = %#v", got)
	}
	if ordered[0]["selected_market"] != "jp" || ordered[0]["market_fit"] != "optional" || ordered[2]["market_fit"] != "native" || ordered[3]["market_fit"] != "native" {
		t.Fatalf("classified providers = %#v", ordered)
	}
	for priority, want := range map[string]int{"p0": 0, "P1": 1, " p2 ": 2, "other": 9} {
		if got := providerPriorityRank(map[string]any{"priority": priority}); got != want {
			t.Fatalf("priority %q = %d, want %d", priority, got, want)
		}
	}
	if providerSupportsMarket(map[string]any{"markets": []string{"br"}}, "jp") || !providerSupportsMarket(map[string]any{}, "jp") {
		t.Fatal("market classification mismatch")
	}
	if providers := (Config{AuthMarket: "br"}).AuthProviders(); len(providers) != 2 || providers[0]["selected_market"] != "br" || providers[0]["key"] != "local" || providers[1]["key"] != "sms" {
		t.Fatalf("auth providers = %#v", providers)
	}
}

func TestConfigEnvironmentHelperEdges(t *testing.T) {
	if got := (Config{}).HTTPAddr(); got != ":8081" {
		t.Fatalf("default address = %q", got)
	}
	if got := (Config{Port: ":9090"}).HTTPAddr(); got != ":9090" {
		t.Fatalf("prefixed address = %q", got)
	}
	if got := (Config{Port: " 9091 "}).HTTPAddr(); got != ":9091" {
		t.Fatalf("numeric address = %q", got)
	}
	if got := (Config{HTTPBindHost: "127.0.0.1", Port: "9092"}).HTTPAddr(); got != "127.0.0.1:9092" {
		t.Fatalf("IPv4 loopback address = %q", got)
	}
	if got := (Config{HTTPBindHost: "::1", Port: "9093"}).HTTPAddr(); got != "[::1]:9093" {
		t.Fatalf("IPv6 loopback address = %q", got)
	}

	t.Setenv("CONFIG_EDGE_DURATION", "17")
	if got := durationEnv("CONFIG_EDGE_DURATION", time.Minute); got != 17*time.Second {
		t.Fatalf("numeric duration = %v", got)
	}
	t.Setenv("CONFIG_EDGE_DURATION", "invalid")
	if got := durationEnv("CONFIG_EDGE_DURATION", time.Minute); got != time.Minute {
		t.Fatalf("invalid duration = %v", got)
	}
	t.Setenv("CONFIG_EDGE_DURATION", "250ms")
	if got := durationEnv("CONFIG_EDGE_DURATION", time.Minute); got != 250*time.Millisecond {
		t.Fatalf("parsed duration = %v", got)
	}
	t.Setenv("CONFIG_EDGE_DURATION", "")
	if got := durationEnv("CONFIG_EDGE_DURATION", time.Minute); got != time.Minute {
		t.Fatalf("empty duration = %v", got)
	}

	for value, want := range map[string]bool{"1": true, "yes": true, "on": true, "0": false, "false": false, "off": false} {
		t.Setenv("CONFIG_EDGE_BOOL", value)
		if got := boolEnv("CONFIG_EDGE_BOOL", !want); got != want {
			t.Fatalf("bool %q = %v", value, got)
		}
	}
	t.Setenv("CONFIG_EDGE_BOOL", "invalid")
	if !boolEnv("CONFIG_EDGE_BOOL", true) {
		t.Fatal("invalid bool did not use fallback")
	}
	t.Setenv("CONFIG_EDGE_BOOL", "")
	if boolEnv("CONFIG_EDGE_BOOL", false) {
		t.Fatal("empty bool did not use fallback")
	}

	t.Setenv("CONFIG_EDGE_FLOAT", "invalid")
	if got := floatEnv("CONFIG_EDGE_FLOAT", .5); got != .5 {
		t.Fatalf("invalid float = %v", got)
	}
	t.Setenv("CONFIG_EDGE_FLOAT", "")
	if got := floatEnv("CONFIG_EDGE_FLOAT", .5); got != .5 {
		t.Fatalf("empty float = %v", got)
	}

	fallback := []string{"fallback"}
	t.Setenv("CONFIG_EDGE_CSV", " alpha, , beta ")
	if got := csvEnv("CONFIG_EDGE_CSV", fallback); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("csv = %#v", got)
	}
	t.Setenv("CONFIG_EDGE_CSV", " , ")
	if got := csvEnv("CONFIG_EDGE_CSV", fallback); !reflect.DeepEqual(got, fallback) {
		t.Fatalf("blank csv = %#v", got)
	}
	t.Setenv("CONFIG_EDGE_CSV", "")
	got := csvEnv("CONFIG_EDGE_CSV", fallback)
	got[0] = "changed"
	if fallback[0] != "fallback" {
		t.Fatal("CSV fallback was not cloned")
	}

	t.Setenv("CONFIG_EDGE_MAP", "one=1,invalid,=missing,empty=, two = 2")
	if got := keyMapEnv("CONFIG_EDGE_MAP"); !reflect.DeepEqual(got, map[string]string{"one": "1", "two": "2"}) {
		t.Fatalf("key map = %#v", got)
	}
	if !providerConfigured("one", " two ") || providerConfigured("one", " ") || !providerConfigured() {
		t.Fatal("provider configured contract mismatch")
	}
}

func TestProductionRedirectURLContract(t *testing.T) {
	for _, value := range []string{"", "https://login.example.com/callback", "HTTPS://login.example.com/callback"} {
		if err := validateProductionRedirectURL("OIDC_REDIRECT_URL", value); err != nil {
			t.Fatalf("value %q: %v", value, err)
		}
	}
	for _, value := range []string{"relative/callback", "://bad", "http://login.example.com/callback"} {
		if err := validateProductionRedirectURL("OIDC_REDIRECT_URL", value); err == nil || !strings.Contains(err.Error(), "OIDC_REDIRECT_URL") {
			t.Fatalf("value %q error = %v", value, err)
		}
	}
}
