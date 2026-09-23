package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	auditcontract "github.com/domainry/domainry-audit-sdk/contract"
	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	"github.com/domainry/domainry-identity/internal/assembly"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	identityprovider "github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	portabilitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/portability"
	runtimeactionusage "github.com/domainry/domainry-identity/internal/infrastructure/runtimeactionusage"
	"github.com/domainry/domainry-identity/internal/platform/config"
	authhttp "github.com/domainry/domainry-identity/internal/transport/http/auth"
	identityhttp "github.com/domainry/domainry-identity/internal/transport/http/identity"
	portabilityhttp "github.com/domainry/domainry-identity/internal/transport/http/portability"
	remotesdkhttp "github.com/domainry/domainry-identity/internal/transport/http/remotesdk"
)

type Server struct {
	core                         *assembly.Core
	routes                       http.Handler
	actions                      *identityapplication.IdentityActionRegistry
	exposures                    *routeExposureResolver
	routeInventory               []string
	identityManagementRoutes     []string
	embeddedPublicAuthRoutes     []string
	embeddedManagementAuthRoutes []string
}

type recordingRouteRegistrar struct {
	mux      *http.ServeMux
	actions  *identityapplication.IdentityActionRegistry
	patterns []string
	err      error
}

func (registrar *recordingRouteRegistrar) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if !registrar.validate(pattern) {
		return
	}
	registrar.patterns = append(registrar.patterns, pattern)
	registrar.mux.HandleFunc(pattern, handler)
}

func (registrar *recordingRouteRegistrar) Handle(pattern string, handler http.Handler) {
	if !registrar.validate(pattern) {
		return
	}
	registrar.patterns = append(registrar.patterns, pattern)
	registrar.mux.Handle(pattern, handler)
}

func (registrar *recordingRouteRegistrar) validate(pattern string) bool {
	if registrar == nil || registrar.mux == nil {
		return false
	}
	if registrar.err != nil {
		return false
	}
	method, routeTemplate, ok := strings.Cut(strings.TrimSpace(pattern), " ")
	if !ok || strings.TrimSpace(method) == "" || strings.TrimSpace(routeTemplate) == "" {
		registrar.err = fmt.Errorf("HTTP route pattern %q must contain method and route template", pattern)
		return false
	}
	if registrar.actions == nil {
		return true
	}
	if _, found := registrar.actions.ResolveHTTP(method, routeTemplate); !found {
		registrar.err = fmt.Errorf("HTTP route %q has no ActionDefinition in the frozen standalone registry", pattern)
		return false
	}
	return true
}

func newRecordingRouteRegistrar(mux *http.ServeMux, actions *identityapplication.IdentityActionRegistry) *recordingRouteRegistrar {
	return &recordingRouteRegistrar{mux: mux, actions: actions}
}

type ServerAssemblyOptions struct {
	Clock           identitysdk.Clock
	ModuleProviders []actioncontract.Provider
}

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
	core, err := assembly.New(ctx, cfg, store, assembly.Options{
		Clock: options.Clock, WorkspaceID: cfg.IdentityWorkspaceID,
		ModuleProviders: append([]actioncontract.Provider(nil), options.ModuleProviders...),
	})
	if err != nil {
		return nil, err
	}
	operationsBinder, ok := core.Binding.(identitysdk.OperationsPersistenceBinding)
	if !ok {
		_ = core.CloseContext(context.Background())
		return nil, fmt.Errorf("Identity SaaS binding does not expose shared Operations persistence")
	}
	if err := operationsBinder.BindOperationsPersistence(); err != nil {
		_ = core.CloseContext(context.Background())
		return nil, fmt.Errorf("bind Identity SaaS shared Operations persistence: %w", err)
	}
	if runtimeURL := strings.TrimSpace(cfg.IdentityActionUsageRuntimeURL); runtimeURL != "" {
		credentialID, credentialErr := runtimeActionUsageCredentialID(cfg)
		if credentialErr != nil {
			_ = core.CloseContext(context.Background())
			return nil, credentialErr
		}
		usageApplication := identitysdk.ApplicationRef{
			WorkspaceID:    identitysdk.WorkspaceID(cfg.IdentityWorkspaceID),
			ApplicationKey: identitysdk.ApplicationKey(strings.TrimSpace(cfg.IdentityActionUsageApplicationKey)),
		}
		if _, registerErr := core.Binding.Applications().Register(ctx, identitysdk.ApplicationRegistration{Application: usageApplication}); registerErr != nil {
			_ = core.CloseContext(context.Background())
			return nil, fmt.Errorf("register Identity Action usage service application: %w", registerErr)
		}
		issuer, available := core.Binding.(runtimeactionusage.ApplicationServiceTokenIssuer)
		if !available {
			_ = core.CloseContext(context.Background())
			return nil, fmt.Errorf("Identity Action usage service token issuer is unavailable")
		}
		tokenSource, tokenErr := runtimeactionusage.NewApplicationServiceTokenSource(issuer, runtimeactionusage.ServiceTokenOptions{
			Application: usageApplication, Audience: identitysdk.ApplicationKey(strings.TrimSpace(cfg.IdentityActionUsageRuntimeAudience)),
			Grant:        identitysdk.ApplicationServiceGrant{Resource: "runtime.action.permission_usages", Action: "query"},
			CredentialID: credentialID,
		})
		if tokenErr != nil {
			_ = core.CloseContext(context.Background())
			return nil, fmt.Errorf("configure Runtime Action usage service identity: %w", tokenErr)
		}
		provider, providerErr := runtimeactionusage.New(runtimeactionusage.Options{
			RuntimeURL: runtimeURL, RequestTimeout: cfg.IdentityActionUsageRequestTimeout, TokenSource: tokenSource,
		})
		if providerErr != nil {
			_ = core.CloseContext(context.Background())
			return nil, fmt.Errorf("configure Runtime Action usage query: %w", providerErr)
		}
		if providerErr = core.PermissionCatalog.UseActionUsageProvider(provider); providerErr != nil {
			_ = core.CloseContext(context.Background())
			return nil, fmt.Errorf("bind Runtime Action usage query: %w", providerErr)
		}
	}
	server, err := newHTTPServer(ctx, cfg, core)
	if err != nil {
		_ = core.CloseContext(context.Background())
		return nil, err
	}
	return server, nil
}

func runtimeActionUsageCredentialID(cfg config.Config) (string, error) {
	workspaceID := strings.TrimSpace(cfg.IdentityWorkspaceID)
	applicationKey := strings.TrimSpace(cfg.IdentityActionUsageApplicationKey)
	credentialID := strings.TrimSpace(cfg.IdentityActionUsageCredentialID)
	credentialScope := url.PathEscape(workspaceID) + "/" + url.PathEscape(applicationKey) + "#" + url.PathEscape(credentialID)
	if strings.TrimSpace(cfg.IdentityApplicationServiceCredentials[credentialScope]) == "" {
		return "", fmt.Errorf("Runtime Action usage service credential scope %q is unavailable", credentialScope)
	}
	return credentialID, nil
}

func newHTTPServer(ctx context.Context, cfg config.Config, core *assembly.Core) (*Server, error) {
	if core == nil || core.IdentityActions == nil {
		return nil, fmt.Errorf("Identity core and Action registry are required")
	}
	applicationCredentials, err := remotesdkhttp.NewApplicationCredentialRegistry(cfg.IdentityApplicationServiceCredentials, cfg.IdentityApplicationPermissionOwners, cfg.IdentityApplicationRateLimitPerMinute, cfg.IdentityApplicationServicePolicies)
	if err != nil {
		return nil, fmt.Errorf("configure Identity application service credentials: %w", err)
	}
	authoringProjection, err := core.IdentityActions.ProjectAuthoringDomain(identitycontract.IdentityAuthoringDomain())
	if err != nil {
		return nil, fmt.Errorf("resolve Identity authoring Actions: %w", err)
	}
	capabilityCatalog, err := identityauthoring.NewAuthoringCatalog(authoringProjection.Domain())
	if err != nil {
		return nil, fmt.Errorf("project Identity authoring catalog: %w", err)
	}
	httpSupport := newHTTPSupport(core.Auth, cfg.CORSAllowedOrigins, httpControlConfig{
		PublicMaxJSONBodyBytes:       int64(cfg.HTTPPublicMaxJSONBodyBytes),
		ManagementMaxJSONBodyBytes:   int64(cfg.HTTPManagementMaxJSONBodyBytes),
		OperationsMaxJSONBodyBytes:   int64(cfg.HTTPOpsMaxJSONBodyBytes),
		PublicRequestTimeout:         cfg.HTTPPublicRequestTimeout,
		ManagementRequestTimeout:     cfg.HTTPManagementRequestTimeout,
		OperationsRequestTimeout:     cfg.HTTPOpsRequestTimeout,
		PublicRateLimitPerMinute:     cfg.HTTPPublicRateLimitPerMinute,
		ManagementRateLimitPerMinute: cfg.HTTPManagementRateLimitPerMinute,
		OperationsRateLimitPerMinute: cfg.HTTPOpsRateLimitPerMinute,
	})
	httpSupport.initializedWorkspaceID = cfg.IdentityWorkspaceID
	if core.WorkspaceResolver != nil {
		httpSupport.hostTokenVerifier = core.Binding.Tokens()
	}
	httpSupport.writesFrozen = core.Store.IdentityWritesFrozen
	actionDefinitions := core.IdentityActions.Definitions()
	browserActionDefinitions, err := browsergateway.ActionDefinitions("/browser")
	if err != nil {
		return nil, fmt.Errorf("resolve standalone browser authentication Actions: %w", err)
	}
	actionDefinitions = append(actionDefinitions, browserActionDefinitions...)
	protocolActionDefinitions, err := standaloneProtocolAuthorizationActions()
	if err != nil {
		return nil, fmt.Errorf("resolve standalone protocol Actions: %w", err)
	}
	actionDefinitions = append(actionDefinitions, protocolActionDefinitions...)
	standaloneActions, err := identityapplication.NewIdentityActionRegistry(actionDefinitions)
	if err != nil {
		return nil, fmt.Errorf("freeze standalone HTTP Action registry: %w", err)
	}
	mux := http.NewServeMux()
	httpSupport.exposures = newRouteExposureResolver(mux, standaloneActions)
	healthRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	registerHealthRoutes(healthRoutes, httpSupport)
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
	portabilityRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	portabilityhttp.NewHandler(portabilityhttp.Dependencies{
		Service: portabilityService, AccessToken: cfg.IdentityOperationsAccessToken,
		DecodeJSON: httpSupport.decodeJSON, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
	}).RegisterRoutes(portabilityRoutes)

	actionAuthorization := identityapplication.NewIdentityActionAuthorizationService(standaloneActions, core.PermissionCatalog)
	httpSupport.actionAuthorization = actionAuthorization
	securityAudit := func(r *http.Request, principal identitymodel.Principal, event, summary string, metadata map[string]any) {
		if r == nil {
			return
		}
		if principal.WorkspaceID == "" {
			principal.WorkspaceID = requestcontext.WorkspaceID(r.Context())
		}
		if principal.WorkspaceID == "" {
			principal.WorkspaceID = strings.TrimSpace(cfg.IdentityWorkspaceID)
		}
		if principal.RequestID == "" {
			principal.RequestID = requestcontext.RequestID(r.Context())
		}
		if principal.CorrelationID == "" {
			principal.CorrelationID = requestcontext.CorrelationID(r.Context())
		}
		if !principal.Known && principal.UserID == "" {
			principal.UserID = "anonymous"
		}
		idempotencyKey := ""
		if principal.RequestID != "" {
			idempotencyKey = strings.TrimSpace(event) + ":" + principal.RequestID
		}
		core.Audit.AppendAuditTelemetry(r.Context(), auditapplication.AuditAppendRequest{
			IdempotencyKey: idempotencyKey, Family: auditcontract.EventFamilyIdentitySecurity, Event: event, ObjectKey: "identity_security", Principal: principal,
			Summary: summary, Metadata: metadata,
		})
	}
	anonymousSecurityAudit := func(r *http.Request, event, summary string, metadata map[string]any) {
		securityAudit(r, identitymodel.Principal{}, event, summary, metadata)
	}
	principalSecurityAudit := func(r *http.Request, principal identitymodel.Principal, event, summary string, metadata map[string]any) {
		securityAudit(r, principal, event, summary, metadata)
	}
	authHandler := authhttp.NewAuthHandler(authhttp.AuthDependencies{
		Passwords: core.Auth, ExternalAccounts: core.Auth, RoleRequests: core.Identity,
		ProviderConfiguration: core.ProviderConfiguration, ProviderFlows: core.ProviderFlows, ProviderCallback: identityprovider.CallbackAdapter{},
		Principal: httpSupport.principal, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError, DecodeJSON: httpSupport.decodeJSON,
		ActionAuthorization: actionAuthorization,
		ProviderFailureAudit: func(r *http.Request, provider, stage string) {
			anonymousSecurityAudit(r, "auth_provider_failed", "Authentication provider failed", map[string]any{
				"provider": provider, "reason": stage, "result": "failed", "error_code": "auth.provider_failed",
			})
		},
		SecurityAudit: anonymousSecurityAudit, SecurityAuditForPrincipal: principalSecurityAudit,
		WritesFrozen: core.Store.IdentityWritesFrozen, FederatedLoginWorkspace: core.AuthStore.FederatedLoginWorkspace,
		ApplicationRegistered: func(applicationCtx context.Context, workspaceID, applicationKey string) (bool, error) {
			if core.WorkspaceResolver == nil {
				if strings.TrimSpace(workspaceID) != core.Applications.WorkspaceID() {
					return false, nil
				}
				return core.Applications.Registered(applicationCtx, applicationKey)
			}
			resolved, err := core.WorkspaceResolver.ResolveWorkspace(applicationCtx, identitysdk.WorkspaceID(workspaceID))
			if err != nil || string(resolved) != workspaceID || applicationKey != cfg.AuthAudience {
				return false, nil
			}
			applications, err := core.Applications.ForWorkspace(workspaceID)
			if err != nil {
				return false, err
			}
			return applications.Registered(applicationCtx, applicationKey)
		},
	})
	authRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	authHandler.RegisterRoutes(authRoutes)

	objects := func() []definitionmodel.ObjectSchema { return core.MetadataRuntime.Schema().Objects }
	governance := identityapplication.NewIdentityGovernanceApplicationServiceWithPermissionSource(core.Identity.Repository(), core.Identity.PermissionDefinitions, func() map[string]definitionmodel.ObjectSchema {
		result := make(map[string]definitionmodel.ObjectSchema, len(objects()))
		for _, object := range objects() {
			result[object.Key] = object
		}
		return result
	})
	roleDefinitionPublication := identityapplication.NewIdentityRoleDefinitionPublicationService(core.Identity, core.PermissionCatalog, core.Metadata)
	accessReviews := identityapplication.NewIdentityAccessReviewApplicationService(identityapplication.IdentityAccessReviewDependencies{
		Identity: core.Identity,
		Audit: func(ctx context.Context, event, recordID string, principal identitymodel.Principal, metadata map[string]any) {
			core.Audit.AppendWithMetadata(ctx, auditcontract.EventFamilyIdentityGovernance, event, "identity_access_review", recordID, principal, event, nil, nil, metadata)
		},
	})
	identityHandler := identityhttp.NewIdentityHandler(identityhttp.IdentityDependencies{
		Users: core.Identity, Roles: core.Identity, Policies: core.Identity, Menus: core.Identity, Authorization: core.Identity,
		EffectiveAccess: core.EffectiveAccess, AccessReviews: accessReviews, Governance: governance,
		Localization: core.Metadata, UserSecurity: core.Auth, Audit: core.Audit,
		Principal: httpSupport.principal, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError, DecodeJSON: httpSupport.decodeJSON,
		SecurityAudit: anonymousSecurityAudit, SecurityPrincipal: principalSecurityAudit,
		Authoring: identityauthoring.NewService(identitypersistence.NewIdentityAuthoringRepository(core.IdentityStore), nil, nil),
		Actions:   standaloneActions, PermissionCatalog: core.PermissionCatalog, ActionAuthorization: actionAuthorization, RoleDefinitions: roleDefinitionPublication,
	})
	identityRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	identityHandler.RegisterRoutes(identityRoutes)

	moduleRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	if err := registerModuleRoutes(moduleRoutes, core.ModuleHTTPProviders, httpSupport); err != nil {
		return nil, err
	}

	directRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	directRoutes.HandleFunc("GET /identity/permissions/effective", httpSupport.action("identity.permissions.effective", func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := core.MetadataSchema.FeaturePermissions(r.Context(), httpSupport.principal(r))
		if err != nil {
			httpSupport.writeServiceError(w, r, err)
			return
		}
		httpSupport.writeJSON(w, http.StatusOK, snapshot)
	}))
	directRoutes.HandleFunc("GET /identity/schema", httpSupport.action("identity.runtime_schema.get", func(w http.ResponseWriter, r *http.Request) {
		httpSupport.writeJSON(w, http.StatusOK, core.MetadataSchema.ForPrincipalLocale(r.Context(), httpSupport.principal(r), r.URL.Query().Get("locale")))
	}))
	directRoutes.HandleFunc("GET /identity/platform-capabilities", httpSupport.action("identity.platform_capabilities.get", func(w http.ResponseWriter, r *http.Request) {
		snapshot := core.MetadataRuntime.SchemaForPrincipal(r.Context(), httpSupport.principal(r))
		httpSupport.writeJSON(w, http.StatusOK, capabilityCatalog.Contract(identityCapabilityInstance(snapshot, core.Identity.PermissionDefinitions())))
	}))

	remoteSDKRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	remotesdkhttp.RegisterRoutes(remoteSDKRoutes, core.Binding, remotesdkhttp.Support{
		DecodeJSON: httpSupport.decodeJSON, WriteJSON: httpSupport.writeJSON, WriteError: httpSupport.writeError,
		WriteServiceError: httpSupport.writeServiceError,
	}, applicationCredentials)
	if _, err := core.Binding.Applications().Register(ctx, identitysdk.ApplicationRegistration{
		Application:  identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: identitysdk.ApplicationKey(cfg.IdentityBrowserApplicationKey)},
		RedirectURLs: append([]string(nil), cfg.IdentityBrowserReturnURLs...),
	}); err != nil {
		return nil, fmt.Errorf("register Identity browser application: %w", err)
	}
	browserGateway, err := browsergateway.New(core.Binding, browsergateway.Config{
		ApplicationKey:     identitysdk.ApplicationKey(cfg.IdentityBrowserApplicationKey),
		DefaultWorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), MaxRequestBodySize: int64(cfg.HTTPPublicMaxJSONBodyBytes),
		Cookie: browsergateway.CookieConfig{Path: "/browser/auth", Secure: cfg.IsProduction(), SameSite: http.SameSiteLaxMode, MaxAge: cfg.AuthRefreshTTL},
	})
	if err != nil {
		return nil, fmt.Errorf("assemble Identity browser gateway: %w", err)
	}
	browserMux := http.NewServeMux()
	if err := browserGateway.RegisterRoutes(browserMux, "/browser"); err != nil {
		return nil, fmt.Errorf("register Identity browser gateway: %w", err)
	}
	browserRoutes := newRecordingRouteRegistrar(mux, standaloneActions)
	for _, definition := range browserActionDefinitions {
		if definition.HTTP == nil {
			return nil, fmt.Errorf("standalone browser Action %q has no HTTP binding", definition.Key)
		}
		browserRoutes.Handle(definition.HTTP.Method+" "+definition.HTTP.RouteTemplate, browserMux)
	}
	standaloneBrowserRoutes := browserRoutes.patterns
	embeddedBrowserRoutes, err := browsergateway.RoutePatterns("")
	if err != nil {
		return nil, fmt.Errorf("resolve embedded browser authentication routes: %w", err)
	}
	embeddedPublicAuthRoutes, embeddedManagementAuthRoutes := embeddedAuthRouteInventory(httpSupport.exposures, authRoutes.patterns, embeddedBrowserRoutes)
	for _, registrar := range []*recordingRouteRegistrar{healthRoutes, portabilityRoutes, authRoutes, identityRoutes, moduleRoutes, directRoutes, remoteSDKRoutes, browserRoutes} {
		if registrar.err != nil {
			return nil, registrar.err
		}
	}
	managementRoutes := append([]string(nil), identityRoutes.patterns...)
	routeInventory := mergeRoutePatterns(
		healthRoutes.patterns,
		portabilityRoutes.patterns,
		authRoutes.patterns,
		identityRoutes.patterns,
		moduleRoutes.patterns,
		directRoutes.patterns,
		remoteSDKRoutes.patterns,
		standaloneBrowserRoutes,
	)
	return &Server{
		core: core, routes: httpSupport.middleware(mux), actions: standaloneActions, exposures: httpSupport.exposures,
		routeInventory:               routeInventory,
		identityManagementRoutes:     managementRoutes,
		embeddedPublicAuthRoutes:     embeddedPublicAuthRoutes,
		embeddedManagementAuthRoutes: embeddedManagementAuthRoutes,
	}, nil
}

func mergeRoutePatterns(groups ...[]string) []string {
	unique := map[string]struct{}{}
	for _, group := range groups {
		for _, pattern := range group {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				unique[pattern] = struct{}{}
			}
		}
	}
	patterns := make([]string, 0, len(unique))
	for pattern := range unique {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	return patterns
}

// embeddedAuthRouteInventory splits AuthHandler routes for embedded mounting.
// Routes whose Action declares an Identity Permission are administration
// semantics and stay owned by AuthHandler even when the SDK browser gateway
// exposes a route at the same path (reset-password accepts Identity's user_id
// contract while the browser SDK contract uses subject_id). Remaining routes
// already served by the browser gateway are not mounted twice.
func embeddedAuthRouteInventory(resolver *routeExposureResolver, authRoutes, browserRoutes []string) ([]string, []string) {
	browserOwned := make(map[string]struct{}, len(browserRoutes))
	for _, pattern := range browserRoutes {
		browserOwned[pattern] = struct{}{}
	}
	publicRoutes := []string{}
	managementRoutes := []string{}
	for _, pattern := range authRoutes {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			continue
		}
		if controlClassOf(resolver.listenerClassesForPattern(method, path)) == listenerClassManagement {
			managementRoutes = append(managementRoutes, pattern)
			continue
		}
		if _, duplicate := browserOwned[pattern]; duplicate {
			continue
		}
		publicRoutes = append(publicRoutes, pattern)
	}
	return publicRoutes, managementRoutes
}

// NewWithCore assembles the HTTP classes over an already-opened embedded
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

// RouteInventory returns every route pattern assembled by the standalone
// Identity server, including auth/browser, management, Remote SDK, Audit,
// portability operations, health probes and direct management routes.
func (s *Server) RouteInventory() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.routeInventory...)
}

// PublicRoutes exposes only browser authentication, protocol discovery,
// JWKS, health, and Remote SDK endpoints. Management and operations paths are
// deliberately indistinguishable from missing routes on this listener.
func (s *Server) PublicRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return listenerOnly(listenerClassPublic, s.exposures, s.routes)
}

// ManagementRoutes exposes only Identity administration and governance APIs.
func (s *Server) ManagementRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return listenerOnly(listenerClassManagement, s.exposures, s.routes)
}

// OperationsRoutes exposes only authenticated migration/cutover operations.
func (s *Server) OperationsRoutes() http.Handler {
	if s == nil || s.routes == nil {
		return nil
	}
	return listenerOnly(listenerClassOperations, s.exposures, s.routes)
}

// IdentityManagementRoutes returns the exact method/path patterns owned by
// the embedded Identity management API. Other routes assembled by the
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
// the Identity management API.
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

func registerHealthRoutes(registrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}, support *httpSupport) {
	ready := func(w http.ResponseWriter, _ *http.Request) {
		support.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "domainry-identity"})
	}
	registrar.HandleFunc("GET /live", ready)
	registrar.HandleFunc("GET /ready", ready)
	registrar.HandleFunc("GET /health", ready)
}
