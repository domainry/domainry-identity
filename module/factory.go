package module

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity-sdk/application"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
	"github.com/domainry/domainry-identity/internal/assembly"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
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
	var store *database.IdentityStore
	if handle == nil {
		store, err = database.OpenContext(ctx, cfg)
	} else {
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
	if err := store.EnsureSchema(ctx); err != nil {
		_ = store.CloseContext(context.Background())
		return nil, fmt.Errorf("prepare Identity module schema: %w", err)
	}
	manifest, err := loadModuleManifest()
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	identityRuntime, err := assembly.NewWithManifest(ctx, cfg, store, manifest, assembly.Options{Clock: factory.Options.Clock})
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	if handle != nil && handle.OrganizationScopeResolver != nil {
		identityRuntime.Identity.UseOrganizationScopeResolver(moduleOrganizationScopeResolver{resolve: handle.OrganizationScopeResolver})
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
		return nil, fmt.Errorf("assemble Identity module management surface: %w", err)
	}
	managementSurface := &moduleHTTPSurface{name: "identity_management", handler: managementServer.Routes()}
	for _, pattern := range managementServer.IdentityManagementRoutes() {
		managementSurface.routes = append(managementSurface.routes, identityhttpapi.Route{Pattern: pattern, Exposures: []identityhttpapi.Exposure{identityhttpapi.ExposureTenantAdmin}})
	}
	for _, pattern := range managementServer.EmbeddedManagementAuthRoutes() {
		managementSurface.routes = append(managementSurface.routes, identityhttpapi.Route{Pattern: pattern, Exposures: []identityhttpapi.Exposure{identityhttpapi.ExposureTenantAdmin}})
	}
	for _, pattern := range managementServer.EmbeddedPublicAuthRoutes() {
		managementSurface.routes = append(managementSurface.routes, identityhttpapi.Route{Pattern: pattern, Exposures: []identityhttpapi.Exposure{identityhttpapi.ExposurePublic}})
	}
	browserGateway, err := browsergateway.New(scopedBinding, browsergateway.Config{
		ApplicationKey:     application.ApplicationKey,
		AllowedReturnURLs:  append([]string(nil), application.RedirectURLs...),
		DefaultWorkspaceID: application.WorkspaceID,
		MaxRequestBodySize: int64(cfg.HTTPPublicMaxJSONBodyBytes),
		Cookie: browsergateway.CookieConfig{
			Path: "/auth", Secure: cfg.IsProduction(), SameSite: http.SameSiteLaxMode, MaxAge: cfg.AuthRefreshTTL,
		},
	})
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("assemble Identity module browser authentication surface: %w", err)
	}
	browserMux := http.NewServeMux()
	if err := browserGateway.RegisterRoutes(browserMux, ""); err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("register Identity module browser authentication surface: %w", err)
	}
	browserPatterns, err := browsergateway.RoutePatterns("")
	if err != nil {
		_ = identityRuntime.CloseContext(ctx)
		return nil, fmt.Errorf("resolve Identity module browser authentication routes: %w", err)
	}
	browserSurface := &moduleHTTPSurface{name: "browser_authentication", handler: browserMux}
	managementOwned := make(map[string]struct{}, len(managementSurface.routes))
	for _, route := range managementSurface.routes {
		managementOwned[route.Pattern] = struct{}{}
	}
	for _, pattern := range browserPatterns {
		if _, owned := managementOwned[pattern]; owned {
			continue
		}
		browserSurface.routes = append(browserSurface.routes, identityhttpapi.Route{
			Pattern: pattern, Exposures: []identityhttpapi.Exposure{identityhttpapi.ExposurePublic, identityhttpapi.ExposureTenantAdmin},
		})
	}
	return &moduleBinding{Binding: scopedBinding, runtime: identityRuntime, application: application, surfaces: []identityhttpapi.Surface{browserSurface, managementSurface}}, nil
}

type moduleOrganizationScopeResolver struct {
	resolve identitysdk.OrganizationScopeResolver
}

func (resolver moduleOrganizationScopeResolver) ResolveIdentityOrganizationScopes(ctx context.Context, workspaceID string, profileIDs []string) (identitymodel.IdentityOrganizationScopeFacts, error) {
	facts, err := resolver.resolve(ctx, workspaceID, append([]string(nil), profileIDs...))
	if err != nil {
		return identitymodel.IdentityOrganizationScopeFacts{}, err
	}
	return identitymodel.IdentityOrganizationScopeFacts{
		TeamIDs: append([]string(nil), facts.TeamIDs...), StoreIDs: append([]string(nil), facts.StoreIDs...),
		TerritoryIDs: append([]string(nil), facts.TerritoryIDs...), WarehouseIDs: append([]string(nil), facts.WarehouseIDs...),
	}, nil
}

type moduleBinding struct {
	identitysdk.Binding
	runtime     *assembly.Core
	application identitysdk.ApplicationRef
	surfaces    []identityhttpapi.Surface
}

func (binding *moduleBinding) HTTPSurfaces() []identityhttpapi.Surface {
	if binding == nil {
		return nil
	}
	return append([]identityhttpapi.Surface(nil), binding.surfaces...)
}

func (binding *moduleBinding) Close(ctx context.Context) error {
	if binding == nil || binding.runtime == nil {
		return nil
	}
	return binding.runtime.CloseContext(ctx)
}

var _ identitysdk.Factory = (*Factory)(nil)
var _ identitysdk.DatabaseFactory = (*Factory)(nil)
var _ identitysdk.Binding = (*moduleBinding)(nil)
var _ identitysdk.ProjectRoleCatalogPublisher = (*moduleBinding)(nil)
var _ identityhttpapi.Provider = (*moduleBinding)(nil)
