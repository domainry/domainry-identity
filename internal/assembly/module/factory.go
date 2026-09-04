package moduleassembly

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	dataexchangemodulehost "github.com/domainry/domainry-data-exchange-sdk/modulehost"
	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity-sdk/application"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	identityapplicationinternal "github.com/domainry/domainry-identity/internal/application/identity"
	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	"github.com/domainry/domainry-identity/internal/assembly"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	portabilitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/portability"
	modulehttptransport "github.com/domainry/domainry-identity/internal/transport/http/module"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

// Factory opens Identity as a true in-process SDK module. The Runtime talks to
// the returned Binding directly; no loopback HTTP server is created.
type Factory struct {
	Options Options
}

func NewFactory(options Options) *Factory {
	return &Factory{Options: options}
}

func (factory *Factory) Open(ctx context.Context, application identitysdk.ApplicationRef) (identitysdk.Binding, error) {
	return factory.open(ctx, application, nil)
}

func (factory *Factory) OpenWithDatabase(ctx context.Context, application identitysdk.ApplicationRef, handle identitysdk.DatabaseHandle) (identitysdk.Binding, error) {
	return factory.open(ctx, application, &handle)
}

// OpenBootstrapWithDatabase opens only the atomic workspace provisioner. It
// creates no compatibility workspace, user, role, credential, browser route,
// or ordinary Identity Binding before the host commits the first tenant.
func (factory *Factory) OpenBootstrapWithDatabase(ctx context.Context, applicationKey identitysdk.ApplicationKey, handle identitysdk.DatabaseHandle) (identitysdk.BootstrapBinding, error) {
	if ctx == nil {
		return nil, &identitysdk.Error{Code: "identity.context_required"}
	}
	if err := ctx.Err(); err != nil {
		return nil, &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.context_unavailable", Cause: err}
	}
	if !applicationKey.Valid() {
		return nil, &identitysdk.Error{Code: "identity.module_application_scope_required"}
	}
	if handle.Migrations == nil {
		return nil, &identitysdk.Error{Code: "identity.module_migration_registrar_required"}
	}
	db, valid := handle.Pool.(*sql.DB)
	if !valid || db == nil {
		return nil, &identitysdk.Error{Code: "identity.module_database_required"}
	}
	cfg, _, err := loadModuleConfig(factory.Options)
	if err != nil {
		return nil, err
	}
	cfg.AuthAudience = string(applicationKey)
	cfg.DatabaseDriver = handle.Driver
	cfg.DatabaseSchema = handle.Schema
	cfg.DBPath = handle.FilePath
	cfg.DatabaseDSN = ""
	cfg.DatabaseMigrationDSN = ""
	store, err := database.OpenBorrowedContext(ctx, cfg, db)
	if err != nil {
		return nil, fmt.Errorf("open Identity bootstrap database: %w", err)
	}
	fail := func(err error) (identitysdk.BootstrapBinding, error) {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	if handle.ModuleMigrations != nil {
		if err := store.UseHostModuleMigrationRegistrar(handle.ModuleMigrations); err != nil {
			return fail(err)
		}
	}
	err = handle.Migrations.ApplyOwnedMigration(ctx, "identity", database.EmbeddedIdentitySchemaMigrationVersion, database.EmbeddedIdentitySchemaMigrationName, database.EmbeddedSchemaChecksum(), store.EnsureEmbeddedSchema)
	if err != nil {
		return fail(fmt.Errorf("prepare Identity bootstrap schema: %w", err))
	}
	if err := store.EnsureEmbeddedModuleBindings(ctx); err != nil {
		return fail(fmt.Errorf("open Identity bootstrap module bindings: %w", err))
	}
	manifest, err := loadModuleManifest()
	if err != nil {
		return fail(err)
	}
	manifest.Roles = identityapplicationinternal.WithStandaloneIdentityRoleDefinitions(manifest.Roles)
	identityStore, err := identitypersistence.NewSQLIdentityStoreWithSchema(ctx, store.DB(), store.SchemaDB(), store.PersistenceEngine(), store.DatabaseSchema(), store.RelationPrefix())
	if err != nil {
		return fail(fmt.Errorf("open Identity bootstrap repository: %w", err))
	}
	identityApp := identityapplicationinternal.NewIdentityApplicationService(identityStore, nil)
	identityApp.ReplaceRoleDefinitions(manifest.Roles)
	identityActions, err := identityapplicationinternal.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		return fail(fmt.Errorf("assemble Identity bootstrap authorization Action registry: %w", err))
	}
	authStore := authpersistence.NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider(), store.IdempotencyMetrics(ctx))
	return &moduleBinding{
		runtime:     &assembly.Core{Store: store, Manifest: manifest, IdentityStore: identityStore, Identity: identityApp, IdentityActions: identityActions, AuthStore: authStore},
		application: identitysdk.ApplicationRef{ApplicationKey: applicationKey},
	}, nil
}

func (factory *Factory) open(ctx context.Context, application identitysdk.ApplicationRef, handle *identitysdk.DatabaseHandle) (identitysdk.Binding, error) {
	if ctx == nil {
		return nil, &identitysdk.Error{Code: "identity.context_required"}
	}
	if err := ctx.Err(); err != nil {
		return nil, &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.context_unavailable", Cause: err}
	}
	if !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return nil, &identitysdk.Error{Code: "identity.module_application_scope_required"}
	}
	cfg, _, err := loadModuleConfig(factory.Options)
	if err != nil {
		return nil, err
	}
	// The embedding Runtime owns the application identity. It is the
	// authoritative token audience, avoiding a split trust scope between
	// Runtime IDENTITY_AUDIENCE and module-local environment configuration.
	cfg.AuthAudience = string(application.ApplicationKey)
	cfg.IdentityWorkspaceID = string(application.WorkspaceID)
	var store *database.IdentityStore
	if handle == nil {
		store, err = database.OpenContext(ctx, cfg)
	} else {
		if handle.Migrations == nil {
			return nil, &identitysdk.Error{Code: "identity.module_migration_registrar_required"}
		}
		db, valid := handle.Pool.(*sql.DB)
		if !valid || db == nil {
			return nil, &identitysdk.Error{Code: "identity.module_database_required"}
		}
		cfg.DatabaseDriver = handle.Driver
		cfg.DatabaseSchema = handle.Schema
		cfg.DBPath = handle.FilePath
		cfg.DatabaseDSN = ""
		cfg.DatabaseMigrationDSN = ""
		store, err = database.OpenBorrowedContext(ctx, cfg, db)
	}
	if err != nil {
		return nil, fmt.Errorf("open Identity module database: %w", err)
	}
	if handle != nil {
		if handle.ModuleMigrations != nil {
			if err := store.UseHostModuleMigrationRegistrar(handle.ModuleMigrations); err != nil {
				_ = store.CloseContext(context.Background())
				return nil, err
			}
		}
		err = handle.Migrations.ApplyOwnedMigration(ctx, "identity", database.EmbeddedIdentitySchemaMigrationVersion, database.EmbeddedIdentitySchemaMigrationName, database.EmbeddedSchemaChecksum(), store.EnsureEmbeddedSchema)
	} else {
		err = store.EnsureSchema(ctx)
	}
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, fmt.Errorf("prepare Identity module schema: %w", err)
	}
	if handle != nil {
		if err := store.EnsureEmbeddedModuleBindings(ctx); err != nil {
			_ = store.CloseContext(context.Background())
			return nil, fmt.Errorf("open Identity embedded module bindings: %w", err)
		}
	}
	manifest, err := loadModuleManifest()
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	identityRuntime, err := assembly.NewWithManifest(ctx, cfg, store, manifest, assembly.Options{Clock: factory.Options.Clock, WorkspaceID: string(application.WorkspaceID)})
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	if handle != nil && handle.BusinessProfileResolver != nil {
		identityRuntime.Identity.UseBusinessProfileResolver(moduleBusinessProfileResolver{resolve: handle.BusinessProfileResolver})
	}
	binding := identityRuntime.Binding
	if binding == nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, &identitysdk.Error{Code: "identity.module_binding_unavailable"}
	}
	scopedBinding, err := identityapplication.Bind(binding, application)
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, err
	}
	managementServer, err := httpserver.NewWithCore(ctx, cfg, identityRuntime)
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("assemble Identity module management adapter: %w", err)
	}
	actionRoutes, err := identityModuleActionRoutes()
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, err
	}
	managementPatterns := append([]string(nil), managementServer.IdentityManagementRoutes()...)
	managementPatterns = append(managementPatterns, managementServer.EmbeddedManagementAuthRoutes()...)
	managementPatterns = append(managementPatterns, managementServer.EmbeddedPublicAuthRoutes()...)
	managementRoutes, err := selectIdentityModuleRoutes(actionRoutes, managementPatterns)
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, err
	}
	managementAdapter := modulehttptransport.NewAdapter("identity_management", managementServer.Routes(), managementRoutes)
	browserGateway, err := browsergateway.New(scopedBinding, browsergateway.Config{
		ApplicationKey:     application.ApplicationKey,
		DefaultWorkspaceID: application.WorkspaceID,
		MaxRequestBodySize: int64(cfg.HTTPPublicMaxJSONBodyBytes),
		Cookie: browsergateway.CookieConfig{
			Path: "/auth", Secure: cfg.IsProduction(), SameSite: http.SameSiteLaxMode, MaxAge: cfg.AuthRefreshTTL,
		},
	})
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("assemble Identity module browser authentication adapter: %w", err)
	}
	browserMux := http.NewServeMux()
	if err := browserGateway.RegisterRoutes(browserMux, ""); err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("register Identity module browser authentication adapter: %w", err)
	}
	browserPatterns, err := browsergateway.RoutePatterns("")
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("resolve Identity module browser authentication routes: %w", err)
	}
	browserRoutes := make([]identityhttpapi.Route, 0, len(browserPatterns))
	managementOwned := make(map[string]struct{}, len(managementRoutes))
	for _, route := range managementRoutes {
		managementOwned[route.Pattern()] = struct{}{}
	}
	var browserOnlyPatterns []string
	for _, pattern := range browserPatterns {
		if _, owned := managementOwned[pattern]; owned {
			continue
		}
		browserOnlyPatterns = append(browserOnlyPatterns, pattern)
	}
	browserRoutes, err = selectIdentityModuleRoutes(actionRoutes, browserOnlyPatterns)
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, err
	}
	browserAdapter := modulehttptransport.NewAdapter("browser_authentication", browserMux, browserRoutes)
	portabilityRepository, err := portabilitypersistence.NewSQLRepository(store)
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("assemble Identity portability Data Exchange provider: %w", err)
	}
	portabilityService, err := portabilityapplication.NewService(portabilityRepository, portabilityapplication.Options{SchemaVersion: database.CurrentIdentitySchemaVersion})
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("assemble Identity portability service: %w", err)
	}
	return &moduleBinding{
		Binding: scopedBinding, runtime: identityRuntime, application: application, adapters: []identityhttpapi.Adapter{browserAdapter, managementAdapter},
		portability: &identityPortabilityDataExchangeProvider{service: portabilityService},
	}, nil
}

func identityModuleActionRoutes() (map[string]identityhttpapi.Route, error) {
	routes := make(map[string]identityhttpapi.Route)
	for _, definition := range identityapplicationinternal.IdentityBuiltinAuthorizationActions() {
		if definition.HTTP == nil {
			continue
		}
		route, err := modulehttp.RouteFromAction(definition)
		if err != nil {
			return nil, fmt.Errorf("project Identity module action %q: %w", definition.Key, err)
		}
		pattern := route.Pattern()
		if previous, duplicate := routes[pattern]; duplicate {
			return nil, fmt.Errorf("Identity module actions %q and %q repeat route %q", previous.Action.Key, route.Action.Key, pattern)
		}
		routes[pattern] = route
	}
	return routes, nil
}

func selectIdentityModuleRoutes(index map[string]identityhttpapi.Route, patterns []string) ([]identityhttpapi.Route, error) {
	routes := make([]identityhttpapi.Route, 0, len(patterns))
	for _, pattern := range patterns {
		route, found := index[pattern]
		if !found {
			return nil, fmt.Errorf("Identity module route %q has no canonical Action", pattern)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

type moduleBusinessProfileResolver struct {
	resolve identitysdk.BusinessProfileResolver
}

func (resolver moduleBusinessProfileResolver) ResolveIdentityBusinessProfiles(ctx context.Context, workspaceID, userID string) ([]identityservice.IdentityBusinessProfile, error) {
	profiles, err := resolver.resolve(ctx, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]identityservice.IdentityBusinessProfile, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, identityservice.IdentityBusinessProfile{BindingKey: profile.BindingKey, ProfileID: profile.ProfileID})
	}
	return out, nil
}

type moduleBinding struct {
	identitysdk.Binding
	runtime     *assembly.Core
	application identitysdk.ApplicationRef
	adapters    []identityhttpapi.Adapter
	portability *identityPortabilityDataExchangeProvider
}

func (binding *moduleBinding) IdentityDataExchangeProviders() (string, dataexchangemodulehost.ImportProvider, dataexchangemodulehost.ExportProvider) {
	if binding == nil || binding.portability == nil {
		return "", nil, nil
	}
	return IdentityPortabilityProviderKey, binding.portability, binding.portability
}

func (binding *moduleBinding) HTTPAdapters() []identityhttpapi.Adapter {
	if binding == nil {
		return nil
	}
	return append([]identityhttpapi.Adapter(nil), binding.adapters...)
}

// AuthorizationActions exposes Identity's complete canonical Action manifest
// to an embedding Runtime. HTTPAdapters intentionally contains only mounted
// browser/management routes; Identity also owns non-HTTP metadata use cases
// whose Permission definitions must participate in the host registry.
func (*moduleBinding) AuthorizationActions() ([]actioncontract.ActionDefinition, error) {
	return identityapplicationinternal.IdentityBuiltinAuthorizationActions(), nil
}

func (binding *moduleBinding) BindPermissionUsageProvider(provider actioncontract.PermissionUsageProvider) error {
	if binding == nil || binding.runtime == nil || binding.runtime.PermissionCatalog == nil {
		return fmt.Errorf("Identity module Permission catalog is unavailable")
	}
	return binding.runtime.PermissionCatalog.UseActionUsageProvider(provider)
}

func (binding *moduleBinding) ApplicationServiceVerifier() identitysdk.ApplicationServiceTokenVerifier {
	if binding == nil || binding.Binding == nil {
		return nil
	}
	services, ok := binding.Binding.(identitysdk.ApplicationServiceVerificationBinding)
	if !ok {
		return nil
	}
	return services.ApplicationServiceVerifier()
}

func (binding *moduleBinding) ActionAssurance() identitysdk.ActionAssurance {
	if binding == nil || binding.Binding == nil {
		return nil
	}
	assurance, ok := binding.Binding.(identitysdk.ActionAssuranceBinding)
	if !ok {
		return nil
	}
	return assurance.ActionAssurance()
}

func (binding *moduleBinding) ChallengeAuthentication() identitysdk.ChallengeAuthentication {
	if binding == nil || binding.Binding == nil {
		return nil
	}
	challenge, ok := binding.Binding.(identitysdk.ChallengeAuthenticationBinding)
	if !ok {
		return nil
	}
	return challenge.ChallengeAuthentication()
}

func (binding *moduleBinding) Close(ctx context.Context) error {
	if binding == nil || binding.runtime == nil {
		return nil
	}
	return binding.runtime.CloseContext(ctx)
}

var _ identitysdk.Factory = (*Factory)(nil)
var _ identitysdk.DatabaseFactory = (*Factory)(nil)
var _ identitysdk.BootstrapDatabaseFactory = (*Factory)(nil)
var _ identitysdk.Binding = (*moduleBinding)(nil)
var _ identitysdk.PermissionUsageProviderBinder = (*moduleBinding)(nil)
var _ identitysdk.SecurityChallengeDeliveryBinder = (*moduleBinding)(nil)
var _ identitysdk.ApplicationServiceVerificationBinding = (*moduleBinding)(nil)
var _ identitysdk.ChallengeAuthenticationBinding = (*moduleBinding)(nil)
var _ identitysdk.ActionAssuranceBinding = (*moduleBinding)(nil)
var _ identitysdk.ProjectRoleCatalogPublisher = (*moduleBinding)(nil)
var _ identityhttpapi.Provider = (*moduleBinding)(nil)
var _ actioncontract.Provider = (*moduleBinding)(nil)
