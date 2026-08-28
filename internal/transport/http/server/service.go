package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	changeplanapplication "github.com/domainry/domainry-identity/internal/application/changeplan"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	"github.com/domainry/domainry-identity/internal/assembly"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	identityprovider "github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	changeplanpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/changeplan"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	portabilitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/portability"
	"github.com/domainry/domainry-identity/internal/platform/config"
	authhttp "github.com/domainry/domainry-identity/internal/transport/http/auth"
	changeplanhttp "github.com/domainry/domainry-identity/internal/transport/http/changeplans"
	identityhttp "github.com/domainry/domainry-identity/internal/transport/http/identity"
	metadatahttp "github.com/domainry/domainry-identity/internal/transport/http/metadata"
	portabilityhttp "github.com/domainry/domainry-identity/internal/transport/http/portability"
	remotesdkhttp "github.com/domainry/domainry-identity/internal/transport/http/remotesdk"
)

type Server struct {
	core                         *assembly.Core
	routes                       http.Handler
	identityManagementRoutes     []string
	embeddedPublicAuthRoutes     []string
	embeddedManagementAuthRoutes []string
}

type recordingRouteRegistrar struct {
	mux      *http.ServeMux
	patterns []string
}

func (registrar *recordingRouteRegistrar) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	registrar.patterns = append(registrar.patterns, pattern)
	registrar.mux.HandleFunc(pattern, handler)
}

type ServerAssemblyOptions struct{ Clock identitysdk.Clock }

func New(ctx context.Context, cfg config.Config) (*Server, error) {
	store, err := database.OpenContext(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open Identity database: %w", err)
	}
	return NewWithStore(ctx, cfg, store, ServerAssemblyOptions{})
}

func NewWithStore(ctx context.Context, cfg config.Config, store *database.IdentityStore, options ServerAssemblyOptions) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("Identity persistence store is required")
	}
	if err := store.EnsureSchema(ctx); err != nil {
		_ = store.CloseContext(context.Background())
		return nil, fmt.Errorf("prepare Identity schema: %w", err)
	}
	core, err := assembly.New(ctx, cfg, store, assembly.Options{Clock: options.Clock})
	if err != nil {
		return nil, err
	}
	server, err := newHTTPServer(ctx, cfg, core)
	if err != nil {
		_ = core.CloseContext(context.Background())
		return nil, err
	}
	return server, nil
}

func newHTTPServer(ctx context.Context, cfg config.Config, core *assembly.Core) (*Server, error) {
	applicationCredentials, err := remotesdkhttp.NewApplicationCredentialRegistry(cfg.IdentityApplicationServiceCredentials, cfg.IdentityApplicationRateLimitPerMinute)
	if err != nil {
		return nil, fmt.Errorf("configure Identity application service credentials: %w", err)
	}
	capabilityCatalog := identityauthoring.NewAuthoringCatalog()
	httpSupport := newHTTPSupport(core.Auth, cfg.CORSAllowedOrigins, httpControlConfig{
		PublicMaxJSONBodyBytes:        int64(cfg.HTTPPublicMaxJSONBodyBytes),
		TenantAdminMaxJSONBodyBytes:   int64(cfg.HTTPTenantAdminMaxJSONBodyBytes),
		OperationsMaxJSONBodyBytes:    int64(cfg.HTTPOpsMaxJSONBodyBytes),
		PublicRequestTimeout:          cfg.HTTPPublicRequestTimeout,
		TenantAdminRequestTimeout:     cfg.HTTPTenantAdminRequestTimeout,
		OperationsRequestTimeout:      cfg.HTTPOpsRequestTimeout,
		PublicRateLimitPerMinute:      cfg.HTTPPublicRateLimitPerMinute,
		TenantAdminRateLimitPerMinute: cfg.HTTPTenantAdminRateLimitPerMinute,
		OperationsRateLimitPerMinute:  cfg.HTTPOpsRateLimitPerMinute,
	})
	httpSupport.writesFrozen = core.Store.IdentityWritesFrozen
	mux := http.NewServeMux()
	registerHealthRoutes(mux, httpSupport)
	portabilityRepository, err := portabilitypersistence.NewSQLRepository(core.Store)
	if err != nil {
		return nil, err
	}
	portabilityService, err := portabilityapplication.NewService(portabilityRepository, portabilityapplication.Options{
		Clock:         func() time.Time { return time.Now().UTC() },
		SchemaVersion: database.CurrentIdentitySchemaVersion,
	})
	if err != nil {
		return nil, err
	}
	portabilityhttp.NewHandler(portabilityhttp.Dependencies{
		Service: portabilityService, AccessToken: cfg.IdentityOperationsAccessToken,
		DecodeJSON: httpSupport.decodeJSON, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
	}).RegisterRoutes(mux)

	authHandler := authhttp.NewAuthHandler(authhttp.AuthDependencies{
		Passwords: core.Auth, ExternalAccounts: core.Auth, RoleRequests: core.Identity,
		ProviderConfiguration: core.ProviderConfiguration, ProviderFlows: core.ProviderFlows, ProviderCallback: identityprovider.CallbackAdapter{},
		Principal: httpSupport.principal, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError, DecodeJSON: httpSupport.decodeJSON,
		Admin: httpSupport.admin, Authenticated: httpSupport.authenticated,
		ProviderFailureAudit: func(*http.Request, string, string) {}, SecurityAudit: func(*http.Request, string, string, map[string]any) {},
		SecurityAuditForPrincipal: func(*http.Request, identitymodel.Principal, string, string, map[string]any) {},
		WritesFrozen:              core.Store.IdentityWritesFrozen, FederatedLoginWorkspace: core.AuthStore.FederatedLoginWorkspace,
		ApplicationRegistered: func(applicationCtx context.Context, workspaceID, applicationKey string) (bool, error) {
			_, lookupErr := core.Binding.Catalog().CurrentRevision(applicationCtx, identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(workspaceID), ApplicationKey: identitysdk.ApplicationKey(applicationKey)})
			if lookupErr == nil {
				return true, nil
			}
			var sdkErr *identitysdk.Error
			if errors.As(lookupErr, &sdkErr) && (sdkErr.Code == "identity.catalog_not_published" || sdkErr.Code == "identity.application_scope_invalid") {
				return false, nil
			}
			return false, lookupErr
		},
	})
	authRoutes := &recordingRouteRegistrar{mux: mux}
	authHandler.RegisterRoutes(authRoutes)

	objects := func() []definitionmodel.ObjectSchema { return core.MetadataRuntime.Schema().Objects }
	governance := identityapplication.NewIdentityGovernanceApplicationServiceWithPermissionSource(core.Identity.Repository(), core.Identity.PermissionDefinitions, func() map[string]definitionmodel.ObjectSchema {
		result := make(map[string]definitionmodel.ObjectSchema, len(objects()))
		for _, object := range objects() {
			result[object.Key] = object
		}
		return result
	})
	accessReviews := identityapplication.NewIdentityAccessReviewApplicationService(identityapplication.IdentityAccessReviewDependencies{
		Identity: core.Identity,
		Audit: func(ctx context.Context, event, recordID string, principal identitymodel.Principal, metadata map[string]any) {
			core.Audit.AppendWithMetadata(ctx, event, "identity_access_review", recordID, principal, event, nil, nil, metadata)
		},
	})
	identityHandler := identityhttp.NewIdentityHandler(identityhttp.IdentityDependencies{
		Users: core.Identity, Roles: core.Identity, Policies: core.Identity, Menus: core.Identity, Authorization: core.Identity,
		EffectiveAccess: core.EffectiveAccess, AccessReviews: accessReviews, Governance: governance,
		Localization: core.Metadata, UserSecurity: core.Auth, Audit: core.Audit,
		Principal: httpSupport.principal, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError, DecodeJSON: httpSupport.decodeJSON,
		SecurityAudit: func(*http.Request, string, string, map[string]any) {}, SecurityPrincipal: func(*http.Request, identitymodel.Principal, string, string, map[string]any) {},
		Authoring: identityauthoring.NewService(identitypersistence.NewIdentityAuthoringRepository(core.IdentityStore), nil, nil),
	})
	identityRoutes := &recordingRouteRegistrar{mux: mux}
	identityHandler.RegisterRoutes(identityRoutes)

	metadataHandler := metadatahttp.NewMetadataHandler(metadatahttp.MetadataDependencies{
		Definitions: core.Metadata, LocalizedTexts: core.Metadata, RuntimeCatalog: core.Metadata,
		IdentityCatalog: core.Identity, Audit: core.Audit, Principal: httpSupport.principal,
		WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError, WriteServiceError: httpSupport.writeServiceError,
		DecodeJSON: httpSupport.decodeJSON, Admin: httpSupport.admin, Authenticated: httpSupport.authenticated, LegacyHeaders: func(http.ResponseWriter) {},
	})
	metadataHandler.RegisterRoutes(mux)
	registerAuditRoutes(mux, core.Audit, httpSupport)

	changePlanStore := changeplanpersistence.NewBusinessChangePlanStore(core.Store)
	changePlanService := changeplanapplication.NewChangePlanApplicationService(changePlanStore, core.MetadataStore, core.AuditStore, metadataChangePlanRuntime{metadata: core.Metadata})
	changePlanProjection := newIdentityChangePlanProjection(core.MetadataRuntime, core.Metadata, core.Identity, capabilityCatalog, httpSupport)
	changePlanHandler := changeplanhttp.NewChangePlansHandler(changeplanhttp.ChangePlansDependencies{
		Service: changePlanService, Principal: httpSupport.principal, Snapshot: changePlanProjection.snapshotSource, Graph: changePlanProjection.graphSource,
		WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError, WriteServiceError: httpSupport.writeServiceError, DecodeJSON: httpSupport.decodeJSON,
	})
	changePlanRoutes := &recordingRouteRegistrar{mux: mux}
	changePlanHandler.RegisterRoutes(changePlanRoutes)
	mux.HandleFunc("GET /domain-system-snapshot", httpSupport.admin(changePlanProjection.systemSnapshot))
	mux.HandleFunc("GET /domain-reference-graph", httpSupport.admin(changePlanProjection.referenceGraph))
	mux.HandleFunc("GET /permissions/effective", httpSupport.authenticated(func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := core.MetadataSchema.FeaturePermissions(r.Context(), httpSupport.principal(r))
		if err != nil {
			httpSupport.writeServiceError(w, r, err)
			return
		}
		httpSupport.writeJSON(w, http.StatusOK, snapshot)
	}))
	mux.HandleFunc("GET /tenant-admin/runtime-schema", httpSupport.authenticated(func(w http.ResponseWriter, r *http.Request) {
		httpSupport.writeJSON(w, http.StatusOK, core.MetadataSchema.ForPrincipalLocale(r.Context(), httpSupport.principal(r), r.URL.Query().Get("locale")))
	}))
	mux.HandleFunc("GET /tenant-admin/platform-capabilities", httpSupport.admin(func(w http.ResponseWriter, r *http.Request) {
		snapshot := core.MetadataRuntime.SchemaForPrincipal(r.Context(), httpSupport.principal(r))
		httpSupport.writeJSON(w, http.StatusOK, capabilityCatalog.Contract(identityCapabilityInstance(snapshot, core.Identity.PermissionDefinitions())))
	}))

	remotesdkhttp.RegisterRoutes(mux, core.Binding, remotesdkhttp.Support{
		DecodeJSON: httpSupport.decodeJSON, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError,
	}, applicationCredentials)
	browserCatalog := identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: identitymodel.InstallationWorkspaceID, ApplicationKey: identitysdk.ApplicationKey(cfg.IdentityBrowserApplicationKey), RedirectURLs: append([]string(nil), cfg.IdentityBrowserReturnURLs...)},
		Resources:       []identitysdk.ResourceDefinition{}, Actions: []identitysdk.ActionDefinition{},
	}
	if _, err := core.Binding.Catalog().Publish(ctx, browserCatalog); err != nil {
		return nil, fmt.Errorf("publish Identity browser application catalog: %w", err)
	}
	browserGateway, err := browsergateway.New(core.Binding, browsergateway.Config{
		ApplicationKey: identitysdk.ApplicationKey(cfg.IdentityBrowserApplicationKey), AllowedReturnURLs: append([]string(nil), cfg.IdentityBrowserReturnURLs...),
		DefaultWorkspaceID: identitymodel.InstallationWorkspaceID, MaxRequestBodySize: int64(cfg.HTTPPublicMaxJSONBodyBytes),
		Cookie: browsergateway.CookieConfig{Path: "/browser/auth", Secure: cfg.IsProduction(), SameSite: http.SameSiteLaxMode, MaxAge: cfg.AuthRefreshTTL},
	})
	if err != nil {
		return nil, fmt.Errorf("assemble Identity browser gateway: %w", err)
	}
	if err := browserGateway.RegisterRoutes(mux, "/browser"); err != nil {
		return nil, fmt.Errorf("register Identity browser gateway: %w", err)
	}
	embeddedBrowserRoutes, err := browsergateway.RoutePatterns("")
	if err != nil {
		return nil, fmt.Errorf("resolve embedded browser authentication routes: %w", err)
	}
	embeddedPublicAuthRoutes, embeddedManagementAuthRoutes := embeddedAuthRouteInventory(authRoutes.patterns, embeddedBrowserRoutes)
	managementRoutes := append([]string(nil), identityRoutes.patterns...)
	managementRoutes = append(managementRoutes, changePlanRoutes.patterns...)
	managementRoutes = append(managementRoutes, "GET /domain-system-snapshot", "GET /domain-reference-graph")
	return &Server{
		core: core, routes: httpSupport.middleware(mux),
		identityManagementRoutes:     managementRoutes,
		embeddedPublicAuthRoutes:     embeddedPublicAuthRoutes,
		embeddedManagementAuthRoutes: embeddedManagementAuthRoutes,
	}, nil
}

func embeddedAuthRouteInventory(authRoutes, browserRoutes []string) ([]string, []string) {
	browserOwned := make(map[string]struct{}, len(browserRoutes))
	for _, pattern := range browserRoutes {
		browserOwned[pattern] = struct{}{}
	}
	publicRoutes := []string{}
	managementRoutes := []string{}
	for _, pattern := range authRoutes {
		if _, duplicate := browserOwned[pattern]; duplicate {
			continue
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			continue
		}
		switch classifyRouteSurface(method, path) {
		case routeSurfaceTenantAdmin:
			managementRoutes = append(managementRoutes, pattern)
		case routeSurfacePublic:
			publicRoutes = append(publicRoutes, pattern)
		}
	}
	return publicRoutes, managementRoutes
}

// NewWithCore assembles the HTTP adapters over an already-opened embedded
// Identity core. The caller remains the sole lifecycle owner of core.
func NewWithCore(ctx context.Context, cfg config.Config, core *assembly.Core) (*Server, error) {
	if core == nil {
		return nil, errors.New("Identity HTTP server requires a core")
	}
	return newHTTPServer(ctx, cfg, core)
}

func identityCapabilityInstance(snapshot metadatamodel.MetadataSchemaSnapshot, permissions map[string]identitymodel.IdentityPermissionDefinition) identityauthoring.Instance {
	instance := identityauthoring.Instance{SchemaHash: snapshot.SchemaHash, ObjectKeys: []string{}, FieldKeys: []identityauthoring.ScopedValues{}, ActionKeys: []string{}, RoleKeys: []string{}, PermissionKeys: []string{}}
	for _, object := range snapshot.Objects {
		instance.ObjectKeys = append(instance.ObjectKeys, object.Key)
		fields := make([]string, 0, len(object.Fields))
		for _, field := range object.Fields {
			fields = append(fields, field.Key)
		}
		sort.Strings(fields)
		instance.FieldKeys = append(instance.FieldKeys, identityauthoring.ScopedValues{Scope: object.Key, Values: fields})
	}
	for _, action := range snapshot.Actions {
		instance.ActionKeys = append(instance.ActionKeys, action.Key)
	}
	for _, role := range snapshot.Roles {
		instance.RoleKeys = append(instance.RoleKeys, role.Key)
	}
	for _, permission := range permissions {
		instance.PermissionKeys = append(instance.PermissionKeys, permission.Key)
	}
	return instance
}

func (s *Server) Routes() http.Handler {
	if s == nil {
		return nil
	}
	return s.routes
}

// PublicRoutes exposes only browser authentication, protocol discovery,
// JWKS, health, and Remote SDK endpoints. Management and operations paths are
// deliberately indistinguishable from missing routes on this listener.
func (s *Server) PublicRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return surfaceOnly(routeSurfacePublic, s.routes)
}

// TenantAdminRoutes exposes only Identity administration and governance APIs.
func (s *Server) TenantAdminRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return surfaceOnly(routeSurfaceTenantAdmin, s.routes)
}

// OperationsRoutes exposes only authenticated migration/cutover operations.
func (s *Server) OperationsRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return surfaceOnly(routeSurfaceOperations, s.routes)
}

// IdentityManagementRoutes returns the exact method/path patterns owned by
// the embedded Identity administration surface. Other routes assembled by the
// standalone server (browser auth, Remote SDK and health) are intentionally
// excluded.
func (s *Server) IdentityManagementRoutes() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.identityManagementRoutes...)
}

// EmbeddedPublicAuthRoutes returns AuthHandler routes that are required by an
// embedded application but are not owned by the SDK browser gateway.
func (s *Server) EmbeddedPublicAuthRoutes() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.embeddedPublicAuthRoutes...)
}

// EmbeddedManagementAuthRoutes returns provider configuration routes owned by
// the Identity tenant-administration surface.
func (s *Server) EmbeddedManagementAuthRoutes() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.embeddedManagementAuthRoutes...)
}
func (s *Server) SDKBinding() identitysdk.Binding {
	if s == nil || s.core == nil {
		return nil
	}
	return s.core.Binding
}
func (s *Server) CloseContext(ctx context.Context) error {
	if s == nil || s.core == nil {
		return nil
	}
	return s.core.CloseContext(ctx)
}

func registerHealthRoutes(mux *http.ServeMux, support *httpSupport) {
	ready := func(w http.ResponseWriter, _ *http.Request) {
		support.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "domainry-identity"})
	}
	mux.HandleFunc("GET /live", ready)
	mux.HandleFunc("GET /ready", ready)
	mux.HandleFunc("GET /health", ready)
}
