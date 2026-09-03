package assembly

import (
	"context"
	"fmt"
	"os"
	"strings"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitysdkadapter "github.com/domainry/domainry-identity/internal/adapter/identitysdk"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	auditrepository "github.com/domainry/domainry-identity/internal/application/auditbinding"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	metadataapplication "github.com/domainry/domainry-identity/internal/application/metadata"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	identityprovider "github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	metadatapersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/metadata"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type Options struct {
	Clock           identitysdk.Clock
	WorkspaceID     string
	ModuleProviders []actioncontract.Provider
}

// Core is the deployment-neutral Identity application graph shared by the
// in-process module and the standalone HTTP service.
type Core struct {
	Store                 *database.IdentityStore
	Manifest              manifestmodel.ManifestSchema
	MetadataStore         metadatapersistence.MetadataStore
	IdentityStore         *identitypersistence.SQLIdentityStore
	AuditBinding          auditsdk.Binding
	ModuleHTTPProviders   []modulehttp.Provider
	AuditStore            auditrepository.AuditRepository
	AuthStore             authpersistence.AuthStore
	Identity              *identityapplication.IdentityApplicationService
	Audit                 *auditapplication.AuditApplicationService
	Auth                  *authapplication.AuthApplicationService
	Applications          *authapplication.AuthApplicationRegistrationService
	MetadataRuntime       *MetadataRuntime
	Metadata              *metadataapplication.MetadataApplicationService
	MetadataSchema        *metadataapplication.MetadataSchemaApplicationService
	ProviderConfiguration *authapplication.AuthProviderApplicationService
	ProviderFlows         *authapplication.AuthProviderFlowApplicationService
	EffectiveAccess       *identityapplication.IdentityEffectiveAccessApplicationService
	IdentityActions       *identityapplication.IdentityActionRegistry
	PermissionCatalog     *identityapplication.IdentityPermissionCatalogApplicationService
	Binding               identitysdk.Binding
}

func New(ctx context.Context, cfg config.Config, store *database.IdentityStore, options Options) (*Core, error) {
	if store == nil {
		return nil, fmt.Errorf("Identity persistence store is required")
	}
	manifest, err := loadManifest(cfg.ManifestPath)
	if err != nil {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	return NewWithManifest(ctx, cfg, store, manifest, options)
}

// NewWithManifest assembles Identity from an implementation-owned manifest.
// The in-process module uses this entrypoint so it never borrows the embedding
// application's TEMPLATE_MANIFEST or filesystem layout.
func NewWithManifest(ctx context.Context, cfg config.Config, store *database.IdentityStore, manifest manifestmodel.ManifestSchema, options Options) (*Core, error) {
	if store == nil {
		return nil, fmt.Errorf("Identity persistence store is required")
	}
	fail := func(err error) (*Core, error) {
		_ = store.CloseContext(context.Background())
		return nil, err
	}
	manifest.Roles = identityapplication.WithStandaloneIdentityRoleDefinitions(manifest.Roles)
	metadataStore := metadatapersistence.NewMetadataStore(store, options.WorkspaceID)
	if err := metadataStore.EnsureManifestMetadata(ctx, manifest); err != nil {
		return fail(fmt.Errorf("install metadata manifest: %w", err))
	}
	identityStore, err := identitypersistence.NewSQLIdentityStoreWithSchema(ctx, store.DB(), store.SchemaDB(), store.PersistenceEngine(), store.DatabaseSchema(), store.RelationPrefix())
	if err != nil {
		return fail(fmt.Errorf("open Identity repository: %w", err))
	}
	workspaceIDInput := strings.TrimSpace(options.WorkspaceID)
	if workspaceIDInput == "" {
		workspaceIDInput = strings.TrimSpace(cfg.IdentityWorkspaceID)
	}
	workspace, err := identitymodel.NewWorkspaceID(workspaceIDInput)
	if err != nil {
		return fail(fmt.Errorf("initialized Identity workspace is required: %w", err))
	}
	workspaceID := workspace.String()
	workspaceCtx := requestcontext.WithWorkspaceID(ctx, workspaceID)
	seed := identityapplication.FromManifest(manifest)
	if err := identityapplication.SyncIdentitySeeds(workspaceCtx, metadataStore, identityStore, manifest, seed, identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "bootstrap Identity admin data")); err != nil {
		return fail(fmt.Errorf("synchronize Identity bootstrap: %w", err))
	}

	auditBinding, err := auditmoduleimpl.NewFactory(auditmoduleimpl.Options{}).OpenModule(ctx,
		auditsdk.ApplicationRef{InstallationID: defaultString(manifest.TemplateID, "domainry-identity")}, identityauditmodule.NewHost(store))
	if err != nil {
		return fail(fmt.Errorf("open Audit module: %w", err))
	}
	if err := auditBinding.Descriptor().Validate(); err != nil {
		return fail(fmt.Errorf("validate Audit module descriptor: %w", err))
	}
	if !auditBinding.Descriptor().Capabilities.HTTPSurface {
		return fail(fmt.Errorf("Audit Binding does not declare its product HTTP surface capability"))
	}
	auditHostBinder, ok := auditBinding.(auditsdk.ApplicationHostBinder)
	if !ok {
		return fail(fmt.Errorf("Audit Binding does not accept application host capabilities"))
	}
	if err := auditHostBinder.BindApplicationHost(identityauditmodule.NewApplicationHost(cfg.AuthJWTSecret)); err != nil {
		return fail(fmt.Errorf("bind Audit application host: %w", err))
	}
	auditProvider, ok := auditBinding.(actioncontract.Provider)
	if !ok {
		return fail(fmt.Errorf("Audit Binding does not provide its authorization Action manifest"))
	}
	moduleProviders := append([]actioncontract.Provider{auditProvider}, options.ModuleProviders...)
	actionDefinitions, moduleHTTPProviders, err := identityActionDefinitionsWithModuleProviders(identityapplication.IdentityBuiltinAuthorizationActions(), moduleProviders...)
	if err != nil {
		return fail(err)
	}
	identityActions, err := identityapplication.NewIdentityActionRegistry(actionDefinitions)
	if err != nil {
		return fail(fmt.Errorf("assemble Identity authorization Action registry: %w", err))
	}
	permissionCatalog, err := identityapplication.NewIdentityPermissionCatalogApplicationService(identityStore, identityActions, workspaceID)
	if err != nil {
		return fail(fmt.Errorf("assemble Identity permission catalog: %w", err))
	}
	for _, owner := range identityActions.PermissionOwners() {
		if _, err := permissionCatalog.ReconcileOwner(workspaceCtx, owner); err != nil {
			return fail(fmt.Errorf("reconcile permissions for %s: %w", owner, err))
		}
	}
	identityApp := identityapplication.NewIdentityApplicationServiceWithPermissionSource(identityStore, permissionCatalog, identityActions)
	identityApp.ReplaceRoleDefinitions(manifest.Roles)
	identityApp.ReplaceAuthorizationPolicies(manifest.PermissionSets, manifest.PermissionSetGroups, manifest.Guardrails)

	auditStore := identityauditmodule.NewAuditStore(auditBinding)
	auditApp := auditapplication.NewAuditApplicationService(auditStore)
	authStore := authpersistence.NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider(), store.IdempotencyMetrics(ctx))
	applicationRegistrations, err := authapplication.NewAuthApplicationRegistrationService(authStore, workspaceID)
	if err != nil {
		return fail(fmt.Errorf("assemble authentication application registry: %w", err))
	}
	authApp := authapplication.NewAuthApplicationService(
		workspaceAuthIdentity{identity: identityApp}, authStore,
		cfg.AuthJWTSecret, cfg.AuthDefaultPassword, cfg.AuthAccessTTL, cfg.AuthRefreshTTL,
		cfg.AuthMaxLoginFailures, cfg.AuthLoginLockDuration, cfg.AuthOTPResendCooldown, cfg.AuthOTPMaxAttempts,
		authpolicy.AuthPasswordPolicy{MinLength: cfg.AuthPasswordMinLength, RequireUpper: cfg.AuthPasswordRequireUpper, RequireLower: cfg.AuthPasswordRequireLower, RequireNumber: cfg.AuthPasswordRequireNumber, RequireSymbol: cfg.AuthPasswordRequireSymbol},
		auditApp.AppendWithMetadata,
	)
	if err := authApp.ConfigureSigningKeys(defaultString(cfg.AuthJWTActiveKID, "legacy-v1"), defaultString(cfg.AuthJWTSecret, config.DevJWTSecret), cfg.AuthJWTVerificationKeys); err != nil {
		return fail(fmt.Errorf("configure signing keys: %w", err))
	}
	if err := authApp.ConfigureTokenMetadata(defaultString(cfg.AuthIssuer, "http://localhost:8081"), defaultString(cfg.AuthAudience, "domainry-runtime")); err != nil {
		return fail(fmt.Errorf("configure token metadata: %w", err))
	}
	if err := authApp.EnsureBootstrapCredential(workspaceCtx, workspaceID); err != nil {
		return fail(fmt.Errorf("ensure bootstrap credential: %w", err))
	}
	if err := authApp.EnsureCredentialsForUsers(workspaceCtx, workspaceID, seed.Users); err != nil {
		return fail(fmt.Errorf("ensure user credentials: %w", err))
	}

	metadataRuntime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{
		TemplateID: defaultString(manifest.TemplateID, "domainry-identity"), TemplateVersion: manifest.Version, Name: manifest.Name,
		Objects: manifest.Objects, Actions: manifest.Actions,
		Roles: manifest.Roles, PermissionSets: manifest.PermissionSets, PermissionSetGroups: manifest.PermissionSetGroups,
		Guardrails: manifest.Guardrails, IdentityProfileExtensions: manifest.IdentityProfileExtensions,
	})
	metadataApp := metadataapplication.NewMetadataApplicationService(metadataapplication.MetadataApplicationDependencies{
		Repository: metadataStore, Permissions: permissionCatalog, Runtime: metadataRuntime, Audit: auditApp,
		AuditAppender: auditApp.AppendWithMetadata, TemplateID: metadataRuntime.Schema().TemplateID,
		Version: metadataRuntime.Schema().TemplateVersion, Name: metadataRuntime.Schema().Name,
	})
	metadataSchemaApp := metadataapplication.NewMetadataSchemaApplicationService(metadataRuntime, metadataStore)
	prepareIdentityCatalogRefresh := func(_ context.Context, snapshot metadatamodel.MetadataSchemaSnapshot) (metadataapplication.MetadataReloadCommit, error) {
		roles := append([]identitymodel.RoleSchema(nil), snapshot.Roles...)
		permissionSets := append([]identitymodel.IdentityPermissionSet(nil), snapshot.PermissionSets...)
		permissionSetGroups := append([]identitymodel.IdentityPermissionSetGroup(nil), snapshot.PermissionSetGroups...)
		guardrails := append([]identitymodel.IdentityGuardrailPolicy(nil), snapshot.Guardrails...)
		return func() {
			identityApp.ReplaceRoleDefinitions(roles)
			identityApp.ReplaceAuthorizationPolicies(permissionSets, permissionSetGroups, guardrails)
		}, nil
	}
	metadataApp.AddReloadObserver(prepareIdentityCatalogRefresh)
	bootstrapPrincipal := identitymodel.Principal{
		Known: true, WorkspaceID: workspaceID, UserID: "system",
		Role: identitymodel.RoleSchema{Key: "system_administrator", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, metadatacontract.MetadataActionReload)},
	}
	if _, err := metadataApp.ReloadMetadata(workspaceCtx, bootstrapPrincipal); err != nil {
		return fail(fmt.Errorf("load persisted Identity metadata: %w", err))
	}

	providerCredentials, err := authStore.ListAuthProviderCredentials(workspaceCtx, workspaceID)
	if err != nil {
		return fail(fmt.Errorf("load authentication provider credentials: %w", err))
	}
	providerConfiguration := authapplication.NewAuthProviderApplicationService(authapplication.MergeTypedAuthProviderCredentials(cfg.AuthProviders(), providerCredentials), cfg.AuthExternalAutoCreateUsers, authStore)
	providerFlows := authapplication.NewAuthProviderFlowApplicationService(authApp, providerConfiguration)
	objects := func() []definitionmodel.ObjectSchema { return metadataRuntime.Schema().Objects }
	actions := func() []definitionmodel.ActionSchema { return metadataRuntime.Schema().Actions }
	effectiveAccess := identityapplication.NewIdentityEffectiveAccessApplicationService(identityapplication.IdentityEffectiveAccessDependencies{
		Identity: identityApp, Objects: objects, Actions: actions,
	})
	binding, err := identitysdkadapter.NewBinding(identitysdkadapter.BindingDependencies{
		Config: cfg, Authentication: authApp, ProviderConfiguration: providerConfiguration,
		ProviderFlows: providerFlows, ProviderCallback: identityprovider.CallbackAdapter{},
		EffectiveAccess: effectiveAccess, Identity: identityApp,
		Applications: applicationRegistrations, Permissions: permissionCatalog,
		Clock: options.Clock, MutationFence: store, LoginTransactions: authStore,
	})
	if err != nil {
		return fail(fmt.Errorf("assemble Identity SDK binding: %w", err))
	}
	return &Core{
		Store: store, Manifest: manifest, MetadataStore: metadataStore, IdentityStore: identityStore,
		AuditBinding: auditBinding, ModuleHTTPProviders: append([]modulehttp.Provider(nil), moduleHTTPProviders...), AuditStore: auditStore, AuthStore: authStore, Identity: identityApp, Audit: auditApp, Auth: authApp,
		Applications:    applicationRegistrations,
		MetadataRuntime: metadataRuntime, Metadata: metadataApp, MetadataSchema: metadataSchemaApp,
		ProviderConfiguration: providerConfiguration, ProviderFlows: providerFlows,
		EffectiveAccess: effectiveAccess, IdentityActions: identityActions, PermissionCatalog: permissionCatalog, Binding: binding,
	}, nil
}

func identityActionDefinitionsWithModuleProviders(base []identitymodel.IdentityActionDefinition, providers ...actioncontract.Provider) ([]identitymodel.IdentityActionDefinition, []modulehttp.Provider, error) {
	definitions := append([]identitymodel.IdentityActionDefinition(nil), base...)
	httpProviders := make([]modulehttp.Provider, 0, len(providers))
	for _, provider := range providers {
		if provider == nil {
			return nil, nil, fmt.Errorf("module Action provider is required")
		}
		provided, err := provider.AuthorizationActions()
		if err != nil {
			return nil, nil, fmt.Errorf("load module authorization Actions: %w", err)
		}
		if len(provided) == 0 {
			return nil, nil, fmt.Errorf("module Action provider returned an empty manifest")
		}
		normalized := make([]identitymodel.IdentityActionDefinition, 0, len(provided))
		for index := range provided {
			definition, normalizeErr := actioncontract.NormalizeDefinition(provided[index])
			if normalizeErr != nil {
				return nil, nil, fmt.Errorf("validate module authorization Action %d: %w", index, normalizeErr)
			}
			normalized = append(normalized, definition)
		}
		httpProvider, exposesHTTP := provider.(modulehttp.Provider)
		if exposesHTTP {
			if err := modulehttp.ValidateSourceOwners(httpProvider); err != nil {
				return nil, nil, fmt.Errorf("validate module authorization owner: %w", err)
			}
		}
		if err := modulehttp.ValidateAuthorizationProjection(normalized, httpProvider); err != nil {
			return nil, nil, fmt.Errorf("validate module authorization projection: %w", err)
		}
		definitions = append(definitions, normalized...)
		if exposesHTTP {
			httpProviders = append(httpProviders, httpProvider)
		}
	}
	return definitions, httpProviders, nil
}

func (core *Core) CloseContext(ctx context.Context) error {
	if core == nil || core.Store == nil {
		return nil
	}
	return core.Store.CloseContext(ctx)
}

func loadManifest(path string) (manifestmodel.ManifestSchema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifestmodel.ManifestSchema{}, fmt.Errorf("read Identity manifest %q: %w", path, err)
	}
	manifest, _, err := manifestmodel.DecodeManifest(raw)
	if err != nil {
		return manifestmodel.ManifestSchema{}, fmt.Errorf("decode Identity manifest: %w", err)
	}
	return manifest, nil
}

func defaultString(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}
