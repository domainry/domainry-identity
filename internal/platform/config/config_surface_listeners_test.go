package config

import (
	"strings"
	"testing"
	"time"
)

func setValidProductionListeners(cfg *Config) {
	cfg.CORSAllowedOrigins = []string{"https://admin.example.com"}
	cfg.HTTPPublicAddr = "0.0.0.0:8081"
	cfg.HTTPTenantAdminAddr = "127.0.0.1:8082"
	cfg.HTTPOpsAddr = "127.0.0.1:8083"
	cfg.IdentityOperationsAccessToken = "operations-access-token"
	cfg.IdentityApplicationRateLimitPerMinute = 1200
	cfg.HTTPPublicMaxJSONBodyBytes = 2 << 20
	cfg.HTTPTenantAdminMaxJSONBodyBytes = 2 << 20
	cfg.HTTPOpsMaxJSONBodyBytes = 1 << 20
	cfg.HTTPPublicRequestTimeout = 30 * time.Second
	cfg.HTTPTenantAdminRequestTimeout = 30 * time.Second
	cfg.HTTPOpsRequestTimeout = 15 * time.Second
	cfg.HTTPPublicRateLimitPerMinute = 6000
	cfg.HTTPTenantAdminRateLimitPerMinute = 3000
	cfg.HTTPOpsRateLimitPerMinute = 1200
}

func TestProductionHTTPControlsRejectDisabledLimits(t *testing.T) {
	valid := Config{
		HTTPPublicMaxJSONBodyBytes: 1, HTTPTenantAdminMaxJSONBodyBytes: 1, HTTPOpsMaxJSONBodyBytes: 1,
		HTTPPublicRequestTimeout: time.Second, HTTPTenantAdminRequestTimeout: time.Second, HTTPOpsRequestTimeout: time.Second,
		HTTPPublicRateLimitPerMinute: 1, HTTPTenantAdminRateLimitPerMinute: 1, HTTPOpsRateLimitPerMinute: 1,
	}
	if err := valid.validateProductionHTTPControls(); err != nil {
		t.Fatal(err)
	}
	invalidInteger := valid
	invalidInteger.HTTPOpsRateLimitPerMinute = 0
	if err := invalidInteger.validateProductionHTTPControls(); err == nil || !strings.Contains(err.Error(), "HTTP_OPS_RATE_LIMIT_PER_MINUTE") {
		t.Fatalf("integer control error=%v", err)
	}
	invalidDuration := valid
	invalidDuration.HTTPPublicRequestTimeout = 0
	if err := invalidDuration.validateProductionHTTPControls(); err == nil || !strings.Contains(err.Error(), "HTTP_PUBLIC_REQUEST_TIMEOUT") {
		t.Fatalf("duration control error=%v", err)
	}
}

func TestValidateProductionSurfaceListeners(t *testing.T) {
	valid := Config{
		HTTPPublicAddr:      "0.0.0.0:8081",
		HTTPTenantAdminAddr: "127.0.0.1:8082",
		HTTPOpsAddr:         "10.0.0.8:8083",
	}
	if err := valid.validateProductionSurfaceListeners(); err != nil {
		t.Fatalf("valid Surface listeners: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing listener", func(cfg *Config) { cfg.HTTPTenantAdminAddr = "" }},
		{"shared listener", func(cfg *Config) { cfg.HTTPOpsAddr = cfg.HTTPTenantAdminAddr }},
		{"public Ops listener", func(cfg *Config) { cfg.HTTPOpsAddr = "0.0.0.0:8083" }},
		{"invalid listener", func(cfg *Config) { cfg.HTTPPublicAddr = "localhost" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.validateProductionSurfaceListeners(); err == nil {
				t.Fatal("expected listener validation failure")
			}
		})
	}
	breakGlass := valid
	breakGlass.HTTPOpsAddr = "0.0.0.0:8083"
	breakGlass.HTTPOpsAllowPublicBindBreakGlass = true
	breakGlass.HTTPOpsPublicBindBreakGlassReason = "reviewed incident access path"
	if err := breakGlass.validateProductionSurfaceListeners(); err != nil {
		t.Fatalf("reviewed break-glass listener: %v", err)
	}
}

func TestProductionSurfaceValidationRemainingConditions(t *testing.T) {
	valid := Config{
		Environment: "production", AuthJWTSecret: "jwt-secret", AuthJWTActiveKID: "jwt-1",
		AuthDefaultPassword: "StrongPassword!", AuthPasswordMinLength: 12,
		IdentityDataSecretKey: "integration-secret", IdentityDataActiveKeyID: "data-1",
	}
	setValidProductionListeners(&valid)
	invalidListeners := valid
	invalidListeners.HTTPOpsAddr = "0.0.0.0:8083"
	if err := invalidListeners.ValidateSecurity(); err == nil || !strings.Contains(err.Error(), "HTTP_OPS_ADDR") {
		t.Fatalf("ValidateSecurity listener error=%v", err)
	}

	for _, test := range []struct {
		name string
		addr string
	}{
		{name: "empty port", addr: "127.0.0.1:"},
		{name: "hostname with break glass", addr: "ops.example.com:8083"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			cfg.HTTPOpsAddr = test.addr
			cfg.HTTPOpsAllowPublicBindBreakGlass = true
			cfg.HTTPOpsPublicBindBreakGlassReason = "reviewed"
			err := cfg.validateProductionSurfaceListeners()
			if test.name == "empty port" && err == nil {
				t.Fatal("empty listener port accepted")
			}
			if test.name != "empty port" && err != nil {
				t.Fatalf("hostname listener error=%v", err)
			}
		})
	}
	missingReason := valid
	missingReason.HTTPOpsAddr = "0.0.0.0:8083"
	missingReason.HTTPOpsAllowPublicBindBreakGlass = true
	if err := missingReason.validateProductionSurfaceListeners(); err == nil {
		t.Fatal("public listener without break-glass reason accepted")
	}
}
