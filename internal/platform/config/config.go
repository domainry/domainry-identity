package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/platform/productbrand"
)

const DevJWTSecret = "dev-generated-auth-secret-change-me"
const DevDefaultAdminPassword = "Domainry@2026"
const DevIdentityDataSecret = "dev-generated-identity-data-secret-change-me"

type Config struct {
	ServiceVersion                    string
	ServiceInstanceID                 string
	ProductBrandName                  string
	Environment                       string
	AppLocale                         string
	HTTPBindHost                      string
	Port                              string
	HTTPPublicAddr                    string
	HTTPTenantAdminAddr               string
	HTTPOpsAddr                       string
	HTTPOpsAllowPublicBindBreakGlass  bool
	HTTPOpsPublicBindBreakGlassReason string
	HTTPReadHeaderTimeout             time.Duration
	HTTPReadTimeout                   time.Duration
	HTTPWriteTimeout                  time.Duration
	HTTPIdleTimeout                   time.Duration
	HTTPShutdownTimeout               time.Duration
	HTTPMaxJSONBodyBytes              int
	HTTPMaxHeaderBytes                int
	HTTPPublicMaxJSONBodyBytes        int
	HTTPTenantAdminMaxJSONBodyBytes   int
	HTTPOpsMaxJSONBodyBytes           int
	HTTPPublicRequestTimeout          time.Duration
	HTTPTenantAdminRequestTimeout     time.Duration
	HTTPOpsRequestTimeout             time.Duration
	HTTPPublicRateLimitPerMinute      int
	HTTPTenantAdminRateLimitPerMinute int
	HTTPOpsRateLimitPerMinute         int
	TelemetryExporter                 string
	TelemetryEndpoint                 string
	TelemetryHeaders                  map[string]string
	TelemetryInsecure                 bool
	TelemetrySampleRatio              float64
	TelemetryExportTimeout            time.Duration
	HealthCheckTimeout                time.Duration
	DatabaseDriver                    string
	DatabaseDSN                       string
	DatabaseMigrationDSN              string
	DatabaseMigrationMode             string
	DatabaseMinSchemaVersion          string
	DatabaseMaxSchemaVersion          string
	DatabaseConnectionMode            string
	DatabaseSchema                    string
	DatabaseMaxOpenConns              int
	DatabaseMaxIdleConns              int
	DatabaseMaxConnections            int
	DatabaseReservedConnections       int
	ServiceReplicaCount               int
	DatabaseConnMaxLifetime           time.Duration
	DatabaseConnMaxIdleTime           time.Duration
	DatabaseConnectTimeout            time.Duration
	DatabaseStatementTimeout          time.Duration
	DatabaseLockTimeout               time.Duration
	DatabaseSSLRootCert               string
	DBPath                            string
	ManifestPath                      string
	MigrationDir                      string
	MigrationSQL                      string
	MigrationBackupDir                string
	MigrationBackupEvidencePath       string
	MigrationBackupLastSuccessAt      string
	MigrationRestoreDrillSuccessAt    string
	MigrationOperator                 string
	MigrationInstanceID               string
	SkipManifestValidation            bool
	// AllowEmptyAuthoringManifest is set only by the trusted configuring
	// Provision lifecycle. It is not loaded from environment configuration.
	AllowEmptyAuthoringManifest           bool
	CORSAllowedOrigins                    []string
	AuthJWTSecret                         string
	AuthJWTActiveKID                      string
	AuthJWTVerificationKeys               map[string]string
	AuthIssuer                            string
	AuthAudience                          string
	AuthMarket                            string
	AuthDefaultPassword                   string
	AuthPasswordMinLength                 int
	AuthPasswordRequireUpper              bool
	AuthPasswordRequireLower              bool
	AuthPasswordRequireNumber             bool
	AuthPasswordRequireSymbol             bool
	AuthAccessTTL                         time.Duration
	AuthRefreshTTL                        time.Duration
	AuthMaxLoginFailures                  int
	AuthLoginLockDuration                 time.Duration
	AuthOTPResendCooldown                 time.Duration
	AuthOTPMaxAttempts                    int
	AuthAllowDevHeaders                   bool
	AuthExternalAutoCreateUsers           bool
	IdentityApplicationServiceCredentials map[string]string
	IdentityApplicationRateLimitPerMinute int
	IdentityOperationsAccessToken         string
	IdentityWorkspaceID                   string
	IdentityBrowserApplicationKey         string
	IdentityBrowserReturnURLs             []string
	IdentityDataSecretKey                 string
	IdentityDataActiveKeyID               string
	IdentityDataDecryptOnlyKeys           map[string]string
}

func FromEnv() Config {
	environment := env("APP_ENV", env("GO_ENV", env("NODE_ENV", "development")))
	return Config{
		ServiceVersion:                        env("DOMAINRY_IDENTITY_VERSION", env("DOMAINRY_RUNTIME_VERSION", "dev")),
		ServiceInstanceID:                     env("IDENTITY_INSTANCE_ID", os.Getenv("RUNTIME_INSTANCE_ID")),
		ProductBrandName:                      productbrand.NameFromEnvironment(),
		Environment:                           environment,
		AppLocale:                             env("APP_LOCALE", "en-US"),
		HTTPBindHost:                          strings.TrimSpace(os.Getenv("HTTP_BIND_HOST")),
		Port:                                  env("PORT", "8081"),
		HTTPPublicAddr:                        strings.TrimSpace(os.Getenv("HTTP_PUBLIC_ADDR")),
		HTTPTenantAdminAddr:                   strings.TrimSpace(os.Getenv("HTTP_TENANT_ADMIN_ADDR")),
		HTTPOpsAddr:                           strings.TrimSpace(os.Getenv("HTTP_OPS_ADDR")),
		HTTPOpsAllowPublicBindBreakGlass:      boolEnv("HTTP_OPS_ALLOW_PUBLIC_BIND_BREAK_GLASS", false),
		HTTPOpsPublicBindBreakGlassReason:     strings.TrimSpace(os.Getenv("HTTP_OPS_PUBLIC_BIND_BREAK_GLASS_REASON")),
		HTTPReadHeaderTimeout:                 durationEnv("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		HTTPReadTimeout:                       durationEnv("HTTP_READ_TIMEOUT", 30*time.Second),
		HTTPWriteTimeout:                      durationEnv("HTTP_WRITE_TIMEOUT", 2*time.Minute),
		HTTPIdleTimeout:                       durationEnv("HTTP_IDLE_TIMEOUT", time.Minute),
		HTTPShutdownTimeout:                   durationEnv("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second),
		HTTPMaxJSONBodyBytes:                  intEnv("HTTP_MAX_JSON_BODY_BYTES", 2<<20),
		HTTPMaxHeaderBytes:                    intEnv("HTTP_MAX_HEADER_BYTES", 1<<20),
		HTTPPublicMaxJSONBodyBytes:            intEnv("HTTP_PUBLIC_MAX_JSON_BODY_BYTES", 2<<20),
		HTTPTenantAdminMaxJSONBodyBytes:       intEnv("HTTP_TENANT_ADMIN_MAX_JSON_BODY_BYTES", 2<<20),
		HTTPOpsMaxJSONBodyBytes:               intEnv("HTTP_OPS_MAX_JSON_BODY_BYTES", 1<<20),
		HTTPPublicRequestTimeout:              durationEnv("HTTP_PUBLIC_REQUEST_TIMEOUT", 30*time.Second),
		HTTPTenantAdminRequestTimeout:         durationEnv("HTTP_TENANT_ADMIN_REQUEST_TIMEOUT", 30*time.Second),
		HTTPOpsRequestTimeout:                 durationEnv("HTTP_OPS_REQUEST_TIMEOUT", 15*time.Second),
		HTTPPublicRateLimitPerMinute:          intEnv("HTTP_PUBLIC_RATE_LIMIT_PER_MINUTE", 6000),
		HTTPTenantAdminRateLimitPerMinute:     intEnv("HTTP_TENANT_ADMIN_RATE_LIMIT_PER_MINUTE", 3000),
		HTTPOpsRateLimitPerMinute:             intEnv("HTTP_OPS_RATE_LIMIT_PER_MINUTE", 1200),
		TelemetryExporter:                     env("TELEMETRY_EXPORTER", env("OTEL_TRACES_EXPORTER", "none")),
		TelemetryEndpoint:                     strings.TrimSpace(env("TELEMETRY_ENDPOINT", os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))),
		TelemetryHeaders:                      keyValueEnv("TELEMETRY_HEADERS", os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")),
		TelemetryInsecure:                     boolEnv("TELEMETRY_INSECURE", false),
		TelemetrySampleRatio:                  floatEnv("TELEMETRY_SAMPLE_RATIO", 1),
		TelemetryExportTimeout:                durationEnv("TELEMETRY_EXPORT_TIMEOUT", 5*time.Second),
		HealthCheckTimeout:                    durationEnv("HEALTH_CHECK_TIMEOUT", 2*time.Second),
		DatabaseDriver:                        env("DATABASE_DRIVER", "sqlite"),
		DatabaseDSN:                           env("DATABASE_DSN", ""),
		DatabaseMigrationDSN:                  strings.TrimSpace(os.Getenv("DATABASE_MIGRATION_DSN")),
		DatabaseMigrationMode:                 databaseMigrationModeEnv(environment),
		DatabaseMinSchemaVersion:              strings.TrimSpace(os.Getenv("DATABASE_MIN_SCHEMA_VERSION")),
		DatabaseMaxSchemaVersion:              strings.TrimSpace(os.Getenv("DATABASE_MAX_SCHEMA_VERSION")),
		DatabaseConnectionMode:                strings.TrimSpace(os.Getenv("DATABASE_CONNECTION_MODE")),
		DatabaseSchema:                        strings.TrimSpace(os.Getenv("DATABASE_SCHEMA")),
		DatabaseMaxOpenConns:                  intEnv("DATABASE_MAX_OPEN_CONNS", 10),
		DatabaseMaxIdleConns:                  intEnv("DATABASE_MAX_IDLE_CONNS", 5),
		DatabaseMaxConnections:                intEnv("DATABASE_MAX_CONNECTIONS", 0),
		DatabaseReservedConnections:           intEnv("DATABASE_RESERVED_CONNECTIONS", 0),
		ServiceReplicaCount:                   intEnv("IDENTITY_REPLICA_COUNT", intEnv("RUNTIME_REPLICA_COUNT", 1)),
		DatabaseConnMaxLifetime:               durationEnv("DATABASE_CONN_MAX_LIFETIME", 30*time.Minute),
		DatabaseConnMaxIdleTime:               durationEnv("DATABASE_CONN_MAX_IDLE_TIME", 5*time.Minute),
		DatabaseConnectTimeout:                durationEnv("DATABASE_CONNECT_TIMEOUT", 10*time.Second),
		DatabaseStatementTimeout:              durationEnv("DATABASE_STATEMENT_TIMEOUT", 30*time.Second),
		DatabaseLockTimeout:                   durationEnv("DATABASE_LOCK_TIMEOUT", 5*time.Second),
		DatabaseSSLRootCert:                   strings.TrimSpace(os.Getenv("DATABASE_SSL_ROOT_CERT")),
		DBPath:                                env("APP_DB_PATH", "data/runtime.db"),
		ManifestPath:                          env("TEMPLATE_MANIFEST", "domainry.template.json"),
		MigrationDir:                          env("MIGRATION_DIR", "migrations"),
		MigrationSQL:                          strings.TrimSpace(os.Getenv("MIGRATION_SQL")),
		MigrationBackupDir:                    env("MIGRATION_BACKUP_DIR", "data/migration-backups"),
		MigrationBackupEvidencePath:           strings.TrimSpace(os.Getenv("MIGRATION_BACKUP_EVIDENCE_PATH")),
		MigrationBackupLastSuccessAt:          strings.TrimSpace(os.Getenv("MIGRATION_BACKUP_LAST_SUCCESS_AT")),
		MigrationRestoreDrillSuccessAt:        strings.TrimSpace(os.Getenv("MIGRATION_RESTORE_DRILL_LAST_SUCCESS_AT")),
		MigrationOperator:                     env("MIGRATION_OPERATOR", "runtime"),
		MigrationInstanceID:                   strings.TrimSpace(os.Getenv("MIGRATION_INSTANCE_ID")),
		SkipManifestValidation:                boolEnv("SKIP_MANIFEST_VALIDATION", false),
		CORSAllowedOrigins:                    csvEnv("CORS_ALLOWED_ORIGINS", []string{"*"}),
		AuthJWTSecret:                         env("AUTH_JWT_SECRET", DevJWTSecret),
		AuthJWTActiveKID:                      env("AUTH_JWT_ACTIVE_KID", "dev-v1"),
		AuthJWTVerificationKeys:               keyMapEnv("AUTH_JWT_VERIFICATION_KEYS"),
		AuthIssuer:                            env("AUTH_ISSUER", "http://localhost:8081"),
		AuthAudience:                          env("AUTH_AUDIENCE", "domainry-runtime"),
		AuthMarket:                            env("AUTH_MARKET", env("APP_MARKET", "jp")),
		AuthDefaultPassword:                   env("AUTH_DEFAULT_PASSWORD", DevDefaultAdminPassword),
		AuthPasswordMinLength:                 intEnv("AUTH_PASSWORD_MIN_LENGTH", 8),
		AuthPasswordRequireUpper:              boolEnv("AUTH_PASSWORD_REQUIRE_UPPER", false),
		AuthPasswordRequireLower:              boolEnv("AUTH_PASSWORD_REQUIRE_LOWER", false),
		AuthPasswordRequireNumber:             boolEnv("AUTH_PASSWORD_REQUIRE_NUMBER", false),
		AuthPasswordRequireSymbol:             boolEnv("AUTH_PASSWORD_REQUIRE_SYMBOL", false),
		AuthAccessTTL:                         durationEnv("AUTH_ACCESS_TTL", 24*time.Hour),
		AuthRefreshTTL:                        durationEnv("AUTH_REFRESH_TTL", 30*24*time.Hour),
		AuthMaxLoginFailures:                  intEnv("AUTH_MAX_LOGIN_FAILURES", 5),
		AuthLoginLockDuration:                 durationEnv("AUTH_LOGIN_LOCK_DURATION", 15*time.Minute),
		AuthOTPResendCooldown:                 durationEnv("AUTH_OTP_RESEND_COOLDOWN", 60*time.Second),
		AuthOTPMaxAttempts:                    intEnv("AUTH_OTP_MAX_ATTEMPTS", 5),
		AuthAllowDevHeaders:                   boolEnv("AUTH_ALLOW_DEV_HEADERS", false),
		AuthExternalAutoCreateUsers:           boolEnv("AUTH_EXTERNAL_AUTO_CREATE_USERS", false),
		IdentityApplicationServiceCredentials: keyMapEnv("IDENTITY_APPLICATION_SERVICE_CREDENTIALS"),
		IdentityApplicationRateLimitPerMinute: intEnv("IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE", 1200),
		IdentityOperationsAccessToken:         strings.TrimSpace(os.Getenv("IDENTITY_OPERATIONS_ACCESS_TOKEN")),
		IdentityWorkspaceID:                   strings.TrimSpace(os.Getenv("IDENTITY_WORKSPACE_ID")),
		IdentityBrowserApplicationKey:         env("IDENTITY_BROWSER_APPLICATION_KEY", "domainry-identity-admin"),
		IdentityBrowserReturnURLs:             csvEnv("IDENTITY_BROWSER_RETURN_URLS", defaultIdentityBrowserReturnURLs(environment)),
		IdentityDataSecretKey:                 env("IDENTITY_DATA_SECRET_KEY", DevIdentityDataSecret),
		IdentityDataActiveKeyID:               env("IDENTITY_DATA_ACTIVE_KEY_ID", "dev-v1"),
		IdentityDataDecryptOnlyKeys:           keyMapEnv("IDENTITY_DATA_DECRYPT_ONLY_KEYS"),
	}
}

func (c Config) EffectiveProductBrandName() string {
	return productbrand.ResolveName(c.ProductBrandName)
}

func databaseMigrationModeEnv(environment string) string {
	if value := strings.ToLower(strings.TrimSpace(os.Getenv("DATABASE_MIGRATION_MODE"))); value != "" {
		return value
	}
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "prod", "production":
		return "verify"
	default:
		return "apply"
	}
}

func (c Config) EffectiveDatabaseMigrationMode() string {
	if value := strings.ToLower(strings.TrimSpace(c.DatabaseMigrationMode)); value != "" {
		return value
	}
	if c.IsProduction() {
		return "verify"
	}
	return "apply"
}

func (c Config) ValidateSecurity() error {
	if !c.IsProduction() {
		return nil
	}
	if c.AuthAllowDevHeaders {
		return fmt.Errorf("AUTH_ALLOW_DEV_HEADERS must be false in production")
	}
	if strings.TrimSpace(c.AuthJWTSecret) == "" || strings.TrimSpace(c.AuthJWTSecret) == DevJWTSecret {
		return fmt.Errorf("AUTH_JWT_SECRET must be set to a non-default value in production")
	}
	if strings.TrimSpace(c.AuthJWTActiveKID) == "" {
		return fmt.Errorf("AUTH_JWT_ACTIVE_KID must be set in production")
	}
	if strings.TrimSpace(c.AuthDefaultPassword) == "" || strings.TrimSpace(c.AuthDefaultPassword) == DevDefaultAdminPassword {
		return fmt.Errorf("AUTH_DEFAULT_PASSWORD must be set to a non-default value in production")
	}
	if strings.TrimSpace(c.IdentityDataSecretKey) == "" || strings.TrimSpace(c.IdentityDataSecretKey) == DevIdentityDataSecret || strings.TrimSpace(c.IdentityDataSecretKey) == c.AuthJWTSecret {
		return fmt.Errorf("IDENTITY_DATA_SECRET_KEY must be set to a non-default value in production")
	}
	if strings.TrimSpace(c.IdentityDataActiveKeyID) == "" {
		return fmt.Errorf("IDENTITY_DATA_ACTIVE_KEY_ID must be set in production")
	}
	if strings.TrimSpace(c.IdentityOperationsAccessToken) == "" {
		return fmt.Errorf("IDENTITY_OPERATIONS_ACCESS_TOKEN must be set in production")
	}
	if c.IdentityApplicationRateLimitPerMinute <= 0 {
		return fmt.Errorf("IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE must be greater than zero in production")
	}
	seenApplicationCredentials := map[string]string{}
	applicationCredentialScopes := make([]string, 0, len(c.IdentityApplicationServiceCredentials))
	for scope := range c.IdentityApplicationServiceCredentials {
		applicationCredentialScopes = append(applicationCredentialScopes, scope)
	}
	sort.Strings(applicationCredentialScopes)
	for _, scope := range applicationCredentialScopes {
		credential := c.IdentityApplicationServiceCredentials[scope]
		scope, credential = strings.TrimSpace(scope), strings.TrimSpace(credential)
		if scope == "" || credential == "" {
			return fmt.Errorf("IDENTITY_APPLICATION_SERVICE_CREDENTIALS contains an empty scope or credential")
		}
		if len(credential) < 32 {
			return fmt.Errorf("IDENTITY_APPLICATION_SERVICE_CREDENTIALS credential for %s must contain at least 32 characters in production", scope)
		}
		if previousScope, duplicate := seenApplicationCredentials[credential]; duplicate {
			return fmt.Errorf("IDENTITY_APPLICATION_SERVICE_CREDENTIALS must not reuse one credential for %s and %s", previousScope, scope)
		}
		if credential == strings.TrimSpace(c.IdentityOperationsAccessToken) || credential == strings.TrimSpace(c.AuthJWTSecret) || credential == strings.TrimSpace(c.IdentityDataSecretKey) {
			return fmt.Errorf("IDENTITY_APPLICATION_SERVICE_CREDENTIALS credential for %s must be independent from operations, JWT, and data-encryption secrets", scope)
		}
		seenApplicationCredentials[credential] = scope
	}
	for _, redirectURL := range c.IdentityBrowserReturnURLs {
		if err := validateProductionRedirectURL("IDENTITY_BROWSER_RETURN_URLS", redirectURL); err != nil {
			return err
		}
	}
	passwordMinLength := c.AuthPasswordMinLength
	if passwordMinLength <= 0 {
		passwordMinLength = 8
	}
	if passwordMinLength < 8 {
		return fmt.Errorf("AUTH_PASSWORD_MIN_LENGTH must be at least 8 in production")
	}
	for _, origin := range c.CORSAllowedOrigins {
		if strings.TrimSpace(origin) == "*" {
			return fmt.Errorf("CORS_ALLOWED_ORIGINS must not contain * in production")
		}
	}
	if err := c.validateProductionSurfaceListeners(); err != nil {
		return err
	}
	if err := c.validateProductionHTTPControls(); err != nil {
		return err
	}
	if strings.TrimSpace(c.TelemetryEndpoint) != "" && c.TelemetryInsecure {
		return fmt.Errorf("TELEMETRY_INSECURE must be false in production")
	}
	return nil
}

// ValidateSaaSDeployment covers security requirements that apply only to the
// standalone Identity service. Module mode intentionally has no application
// service credential because its Runtime calls the in-process Binding.
func (c Config) ValidateSaaSDeployment() error {
	if c.IsProduction() && len(c.IdentityApplicationServiceCredentials) == 0 {
		return fmt.Errorf("IDENTITY_APPLICATION_SERVICE_CREDENTIALS must register at least one Runtime application in a production SaaS deployment")
	}
	return nil
}

func (c Config) validateProductionHTTPControls() error {
	integerControls := []struct {
		name  string
		value int
	}{
		{"HTTP_PUBLIC_MAX_JSON_BODY_BYTES", c.HTTPPublicMaxJSONBodyBytes},
		{"HTTP_TENANT_ADMIN_MAX_JSON_BODY_BYTES", c.HTTPTenantAdminMaxJSONBodyBytes},
		{"HTTP_OPS_MAX_JSON_BODY_BYTES", c.HTTPOpsMaxJSONBodyBytes},
		{"HTTP_PUBLIC_RATE_LIMIT_PER_MINUTE", c.HTTPPublicRateLimitPerMinute},
		{"HTTP_TENANT_ADMIN_RATE_LIMIT_PER_MINUTE", c.HTTPTenantAdminRateLimitPerMinute},
		{"HTTP_OPS_RATE_LIMIT_PER_MINUTE", c.HTTPOpsRateLimitPerMinute},
	}
	for _, control := range integerControls {
		if control.value <= 0 {
			return fmt.Errorf("%s must be greater than zero in production", control.name)
		}
	}
	durationControls := []struct {
		name  string
		value time.Duration
	}{
		{"HTTP_PUBLIC_REQUEST_TIMEOUT", c.HTTPPublicRequestTimeout},
		{"HTTP_TENANT_ADMIN_REQUEST_TIMEOUT", c.HTTPTenantAdminRequestTimeout},
		{"HTTP_OPS_REQUEST_TIMEOUT", c.HTTPOpsRequestTimeout},
	}
	for _, control := range durationControls {
		if control.value <= 0 {
			return fmt.Errorf("%s must be greater than zero in production", control.name)
		}
	}
	return nil
}

func defaultIdentityBrowserReturnURLs(environment string) []string {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "prod", "production":
		return nil
	default:
		return []string{"http://localhost:3100/auth/callback", "http://127.0.0.1:3100/auth/callback"}
	}
}

func (c Config) validateProductionSurfaceListeners() error {
	listeners := []struct {
		name string
		addr string
	}{
		{"HTTP_PUBLIC_ADDR", c.HTTPPublicAddr},
		{"HTTP_TENANT_ADMIN_ADDR", c.HTTPTenantAdminAddr},
		{"HTTP_OPS_ADDR", c.HTTPOpsAddr},
	}
	seen := map[string]string{}
	for _, listener := range listeners {
		addr := strings.TrimSpace(listener.addr)
		if addr == "" {
			return fmt.Errorf("%s must be set in production", listener.name)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil || strings.TrimSpace(port) == "" {
			return fmt.Errorf("%s must be a valid host:port listener address", listener.name)
		}
		key := strings.ToLower(net.JoinHostPort(strings.Trim(host, "[]"), port))
		if owner := seen[key]; owner != "" {
			return fmt.Errorf("%s must not share listener address %q with %s", listener.name, addr, owner)
		}
		seen[key] = listener.name
	}
	host, _, _ := net.SplitHostPort(strings.TrimSpace(c.HTTPOpsAddr))
	host = strings.Trim(host, "[]")
	private := false
	if ip := net.ParseIP(host); ip != nil {
		private = ip.IsLoopback() || ip.IsPrivate()
	}
	if !private {
		if !c.HTTPOpsAllowPublicBindBreakGlass || strings.TrimSpace(c.HTTPOpsPublicBindBreakGlassReason) == "" {
			return fmt.Errorf("HTTP_OPS_ADDR must bind a loopback/private IP in production unless reviewed break-glass is enabled with a reason")
		}
	}
	return nil
}

func (c Config) IsProduction() bool {
	switch strings.ToLower(strings.TrimSpace(c.Environment)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}

func (c Config) AuthProviders() []map[string]any {
	providers := []map[string]any{
		{"key": "local", "label": "Password", "enabled": true, "type": "password", "priority": "p0", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff", "customer"}},
		{"key": "sms", "label": "SMS verification code", "enabled": false, "type": "otp", "priority": "p0", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"customer"}},
		{"key": "feishu", "label": "Feishu", "enabled": false, "type": "oidc", "auth_url": "https://accounts.feishu.cn/open-apis/authen/v1/authorize", "scope": "openid", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "lark", "label": "Lark", "enabled": false, "type": "oidc", "auth_url": "https://accounts.larksuite.com/open-apis/authen/v1/authorize", "scope": "openid", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "google", "label": "Google", "enabled": false, "type": "oidc", "issuer": "https://accounts.google.com", "auth_url": "https://accounts.google.com/o/oauth2/v2/auth", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff", "customer"}},
		{"key": "apple", "label": "Sign in with Apple", "enabled": false, "type": "oidc", "issuer": "https://appleid.apple.com", "auth_url": "https://appleid.apple.com/auth/authorize", "scope": "openid email name", "priority": "p1", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"customer"}},
		{"key": "slack", "label": "Sign in with Slack", "enabled": false, "type": "oidc", "issuer": "https://slack.com", "auth_url": "https://slack.com/openid/connect/authorize", "scope": "openid profile email", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "microsoft", "label": "Microsoft Entra ID", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff"}},
		{"key": "microsoft_entra", "label": "Microsoft Entra ID", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff"}},
		{"key": "okta", "label": "Okta", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "onelogin", "label": "OneLogin", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "keycloak", "label": "Keycloak", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "auth0", "label": "Auth0", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff", "customer"}},
		{"key": "authentik", "label": "Authentik", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "gitlab", "label": "GitLab", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "adfs", "label": "ADFS", "enabled": false, "type": "saml", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "gmo_trustlogin", "label": "GMO TrustLogin", "enabled": false, "type": "saml", "priority": "p1", "market": "global", "markets": []string{"global", "jp"}, "channels": []string{"staff"}},
		{"key": "hennge_one", "label": "HENNGE One", "enabled": false, "type": "saml", "priority": "p1", "market": "global", "markets": []string{"global", "jp"}, "channels": []string{"staff"}},
		{"key": "iij_id", "label": "IIJ ID", "enabled": false, "type": "saml", "priority": "p1", "market": "global", "markets": []string{"global", "jp"}, "channels": []string{"staff"}},
		{"key": "oidc", "label": "Custom OIDC", "enabled": false, "type": "oidc", "scope": "openid email profile", "priority": "p2", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff", "customer"}},
		{"key": "oauth2", "label": "Custom OAuth 2.0", "enabled": false, "type": "oauth2", "adapter": "generic_oauth2", "priority": "p2", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff", "customer"}},
		{"key": "saml", "label": "Custom SAML", "enabled": false, "type": "saml", "priority": "p2", "market": "global", "markets": []string{"global", "jp", "br"}, "channels": []string{"staff"}},
		{"key": "line", "label": "LINE Login", "enabled": false, "type": "oidc", "issuer": "https://access.line.me", "auth_url": "https://access.line.me/oauth2/v2.1/authorize", "scope": "openid profile email", "priority": "p1", "market": "global", "markets": []string{"global", "jp"}, "channels": []string{"customer"}},
		{"key": "line_works", "label": "LINE WORKS", "enabled": false, "type": "oidc", "scope": "openid profile email", "priority": "p1", "market": "global", "markets": []string{"global", "jp"}, "channels": []string{"staff"}},
		{"key": "github", "label": "GitHub", "enabled": false, "type": "oauth2", "adapter": "github", "auth_url": "https://github.com/login/oauth/authorize", "token_url": "https://github.com/login/oauth/access_token", "userinfo_url": "https://api.github.com/user", "scope": "read:user user:email", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff", "customer"}},
		{"key": "instagram", "label": "Instagram", "enabled": false, "type": "oauth2", "adapter": "instagram", "auth_url": "https://www.instagram.com/oauth/authorize", "token_url": "https://api.instagram.com/oauth/access_token", "userinfo_url": "https://graph.instagram.com/me", "scope": "instagram_business_basic", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"customer"}},
		{"key": "discord", "label": "Discord", "enabled": false, "type": "oauth2", "adapter": "generic_oauth2", "auth_url": "https://discord.com/oauth2/authorize", "token_url": "https://discord.com/api/v10/oauth2/token", "userinfo_url": "https://discord.com/api/v10/users/@me", "scope": "identify email", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"customer"}},
		{"key": "dingtalk", "label": "DingTalk", "enabled": false, "type": "oauth2", "adapter": "dingtalk", "auth_url": "https://login.dingtalk.com/oauth2/auth", "token_url": "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", "userinfo_url": "https://api.dingtalk.com/v1.0/contact/users/me", "scope": "openid", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "wechat_web", "label": "WeChat Web OAuth", "enabled": false, "type": "oauth2", "adapter": "wechat_web", "auth_url": "https://open.weixin.qq.com/connect/oauth2/authorize", "token_url": "https://api.weixin.qq.com/sns/oauth2/access_token", "userinfo_url": "https://api.weixin.qq.com/sns/userinfo", "scope": "snsapi_userinfo", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"customer"}},
		{"key": "wecom", "label": "WeCom", "enabled": false, "type": "oauth2", "adapter": "wecom", "auth_url": "https://open.weixin.qq.com/connect/oauth2/authorize", "token_url": "https://qyapi.weixin.qq.com/cgi-bin/gettoken", "userinfo_url": "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo", "scope": "snsapi_base", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "enterprise_wechat", "label": "Enterprise WeChat", "enabled": false, "type": "oauth2", "adapter": "wecom", "auth_url": "https://open.weixin.qq.com/connect/oauth2/authorize", "token_url": "https://qyapi.weixin.qq.com/cgi-bin/gettoken", "userinfo_url": "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo", "scope": "snsapi_base", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"staff"}},
		{"key": "wechat_mini_program", "label": "WeChat Mini Program", "enabled": false, "type": "code_exchange", "adapter": "wechat_mini_program", "token_url": "https://api.weixin.qq.com/sns/jscode2session", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"customer"}},
		{"key": "alipay_mini_program", "label": "Alipay Mini Program", "enabled": false, "type": "code_exchange", "adapter": "alipay_mini_program", "token_url": "https://openapi.alipay.com/gateway.do", "priority": "p1", "market": "global", "markets": []string{"global"}, "channels": []string{"customer"}},
	}
	return providersForMarket(providers, c.AuthMarket)
}

func providersForMarket(providers []map[string]any, market string) []map[string]any {
	market = strings.ToLower(strings.TrimSpace(market))
	if market == "" {
		market = "jp"
	}
	for _, provider := range providers {
		provider["selected_market"] = market
		if priorities, ok := provider["priority_by_market"].(map[string]string); ok {
			if priority := strings.TrimSpace(priorities[market]); priority != "" {
				provider["priority"] = priority
			}
		}
		if !providerSupportsMarket(provider, market) {
			provider["market_fit"] = "optional"
		} else {
			provider["market_fit"] = "native"
		}
	}
	sort.SliceStable(providers, func(i, j int) bool {
		left := providerPriorityRank(providers[i])
		right := providerPriorityRank(providers[j])
		if left != right {
			return left < right
		}
		return fmt.Sprint(providers[i]["label"]) < fmt.Sprint(providers[j]["label"])
	})
	return providers
}

func providerSupportsMarket(provider map[string]any, market string) bool {
	markets, _ := provider["markets"].([]string)
	for _, item := range markets {
		if strings.EqualFold(item, market) || strings.EqualFold(item, "global") {
			return true
		}
	}
	return len(markets) == 0
}

func providerPriorityRank(provider map[string]any) int {
	switch strings.ToLower(strings.TrimSpace(fmt.Sprint(provider["priority"]))) {
	case "p0":
		return 0
	case "p1":
		return 1
	case "p2":
		return 2
	default:
		return 9
	}
}

func (c Config) HTTPAddr() string {
	port := strings.TrimSpace(c.Port)
	if port == "" {
		port = "8081"
	}
	port = strings.TrimPrefix(port, ":")
	host := strings.TrimSpace(c.HTTPBindHost)
	if host == "" {
		return ":" + port
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}
