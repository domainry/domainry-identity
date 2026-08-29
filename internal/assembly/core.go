package assembly

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitysdkadapter "github.com/domainry/domainry-identity/internal/adapter/identitysdk"
	auditapplication "github.com/domainry/domainry-identity/internal/application/audit"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	metadataapplication "github.com/domainry/domainry-identity/internal/application/metadata"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
	identityprovider "github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	auditpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/audit"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitycatalogpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identitycatalog"
	metadatapersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/metadata"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type Options struct {
	Clock identitysdk.Clock
}

// Core is the deployment-neutral Identity application graph shared by the
// in-process module and the standalone HTTP service.
type Core struct {
	Store                 *database.IdentityStore
	Manifest              manifestmodel.ManifestSchema
	MetadataStore         metadatapersistence.MetadataStore
	IdentityStore         *identitypersistence.SQLIdentityStore
	AuditStore            auditpersistence.AuditStore
	AuthStore             authpersistence.AuthStore
	Identity              *identityapplication.IdentityApplicationService
	Audit                 *auditapplication.AuditApplicationService
	Auth                  *authapplication.AuthApplicationService
	MetadataRuntime       *MetadataRuntime
	Metadata              *metadataapplication.MetadataApplicationService
	MetadataSchema        *metadataapplication.MetadataSchemaApplicationService
	ProviderConfiguration *authapplication.AuthProviderApplicationService
	ProviderFlows         *authapplication.AuthProviderFlowApplicationService
	EffectiveAccess       *identityapplication.IdentityEffectiveAccessApplicationService
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
	metadataStore := metadatapersistence.NewMetadataStore(store)
	if err := metadataStore.EnsureManifestMetadata(ctx, manifest); err != nil {
		return fail(fmt.Errorf("install metadata manifest: %w", err))
	}
	identityStore, err := identitypersistence.NewSQLIdentityStoreWithSchema(ctx, store.DB(), store.SchemaDB(), store.PersistenceDialect(), store.DatabaseSchema(), store.RelationPrefix())
	if err != nil {
		return fail(fmt.Errorf("open Identity repository: %w", err))
	}
	workspaceCtx := requestcontext.WithWorkspaceID(ctx, identitymodel.InstallationWorkspaceID)
	seed := identityapplication.FromManifest(manifest)
	if err := identityapplication.SyncIdentitySeeds(workspaceCtx, metadataStore, identityStore, manifest, seed, identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "bootstrap Identity admin data")); err != nil {
		return fail(fmt.Errorf("synchronize Identity bootstrap: %w", err))
	}

	permissions := identityapplication.MergeIdentityPermissions(seed.Permissions, identityapplication.IdentityPermissionsFromRoles(manifest.Roles, manifest.Objects, cfg.AppLocale))
	identityApp := identityapplication.NewIdentityApplicationService(identityStore, permissions)
	identityApp.ReplaceRoleDefinitions(manifest.Roles)
	identityApp.ReplaceAuthorizationCatalogs(manifest.PermissionSets, manifest.PermissionSetGroups, manifest.Guardrails)

	auditStore := auditpersistence.NewAuditStore(store)
	auditApp := auditapplication.NewAuditApplicationService(auditStore)
	authStore := authpersistence.NewAuthStoreWithKeyProvider(identityStore, store.SecretKeyProvider(), store.IdempotencyMetrics(ctx))
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
	if err := authApp.EnsureBootstrapCredential(workspaceCtx, identitymodel.InstallationWorkspaceID); err != nil {
		return fail(fmt.Errorf("ensure bootstrap credential: %w", err))
	}
	if err := authApp.EnsureCredentialsForUsers(workspaceCtx, identitymodel.InstallationWorkspaceID, seed.Users); err != nil {
		return fail(fmt.Errorf("ensure user credentials: %w", err))
	}

	metadataRuntime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{
		TemplateID: defaultString(manifest.TemplateID, "domainry-identity"), TemplateVersion: manifest.Version, Name: manifest.Name,
		Objects: manifest.Objects, Views: manifest.Views, Actions: manifest.Actions,
		Roles: manifest.Roles, PermissionSets: manifest.PermissionSets, PermissionSetGroups: manifest.PermissionSetGroups,
		Guardrails: manifest.Guardrails, IdentityProfileExtensions: manifest.IdentityProfileExtensions,
	})
	metadataApp := metadataapplication.NewMetadataApplicationService(metadataapplication.MetadataApplicationDependencies{
		Repository: metadataStore, Runtime: metadataRuntime, Audit: auditApp,
		AuditAppender: auditApp.AppendWithMetadata, TemplateID: metadataRuntime.Schema().TemplateID,
		Version: metadataRuntime.Schema().TemplateVersion, Name: metadataRuntime.Schema().Name,
	})
	metadataApp.UsePermissionDefinitionSource(func() []identitymodel.IdentityPermissionDefinition {
		return identityApp.ListPermissions(context.Background())
	})
	metadataSchemaApp := metadataapplication.NewMetadataSchemaApplicationService(metadataRuntime, metadataStore)
	refreshIdentityCatalog := func(snapshot metadatamodel.MetadataSchemaSnapshot) {
		identityApp.ReplacePermissionDefinitions(identityapplication.MergeIdentityPermissions(seed.Permissions, identityapplication.IdentityPermissionsFromRuntime(snapshot.Roles, snapshot.Objects, snapshot.Actions, cfg.AppLocale)))
		identityApp.ReplaceRoleDefinitions(snapshot.Roles)
		identityApp.ReplaceAuthorizationCatalogs(snapshot.PermissionSets, snapshot.PermissionSetGroups, snapshot.Guardrails)
	}
	metadataApp.AddReloadObserver(refreshIdentityCatalog)
	bootstrapPrincipal := identitymodel.Principal{
		Known: true, WorkspaceID: identitymodel.InstallationWorkspaceID, UserID: "system",
		Role: identitymodel.RoleSchema{Key: "system_administrator", Permissions: []string{"workspace.admin"}},
	}
	if _, err := metadataApp.ReloadMetadata(workspaceCtx, bootstrapPrincipal); err != nil {
		return fail(fmt.Errorf("load persisted Identity metadata: %w", err))
	}

	providerCredentials, err := authStore.ListAuthProviderCredentials(workspaceCtx, identitymodel.InstallationWorkspaceID)
	if err != nil {
		return fail(fmt.Errorf("load authentication provider credentials: %w", err))
	}
	providerConfiguration := authapplication.NewAuthProviderApplicationService(authapplication.MergeTypedAuthProviderCredentials(cfg.AuthProviders(), providerCredentials), cfg.AuthExternalAutoCreateUsers, authStore)
	providerFlows := authapplication.NewAuthProviderFlowApplicationService(authApp, providerConfiguration)
	objects := func() []definitionmodel.ObjectSchema { return metadataRuntime.Schema().Objects }
	actions := func() []definitionmodel.ActionSchema { return metadataRuntime.Schema().Actions }
	effectiveAccess := identityapplication.NewIdentityEffectiveAccessApplicationService(identityapplication.IdentityEffectiveAccessDependencies{
		Identity: identityApp, Objects: objects, Actions: actions,
		RecordScopeAllows: func(context.Context, string, string, string, identitymodel.Principal) (bool, error) { return true, nil },
	})
	binding, err := identitysdkadapter.NewBinding(identitysdkadapter.BindingDependencies{
		Config: cfg, Authentication: authApp, ProviderConfiguration: providerConfiguration,
		ProviderFlows: providerFlows, ProviderCallback: identityprovider.CallbackAdapter{},
		EffectiveAccess: effectiveAccess, Identity: identityApp, Metadata: metadataRuntime,
		Clock: options.Clock, Catalog: identitycatalogpersistence.NewStore(identityStore),
		MutationFence: store, LoginTransactions: authStore,
		CatalogPublished: func(catalogs []identitysdk.AuthorizationCatalog) {
			metadataApp.ReplaceAuthorizationObjects(authorizationCatalogObjects(catalogs))
		},
	})
	if err != nil {
		return fail(fmt.Errorf("assemble Identity SDK binding: %w", err))
	}
	return &Core{
		Store: store, Manifest: manifest, MetadataStore: metadataStore, IdentityStore: identityStore,
		AuditStore: auditStore, AuthStore: authStore, Identity: identityApp, Audit: auditApp, Auth: authApp,
		MetadataRuntime: metadataRuntime, Metadata: metadataApp, MetadataSchema: metadataSchemaApp,
		ProviderConfiguration: providerConfiguration, ProviderFlows: providerFlows,
		EffectiveAccess: effectiveAccess, Binding: binding,
	}, nil
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

func authorizationCatalogObjects(catalogs []identitysdk.AuthorizationCatalog) []definitionmodel.ObjectSchema {
	byKey := map[string]definitionmodel.ObjectSchema{}
	for _, catalog := range catalogs {
		for _, resource := range catalog.Resources {
			key := strings.TrimSpace(string(resource.Key))
			if key == "" {
				continue
			}
			object := byKey[key]
			object.Key = key
			fields := map[string]bool{}
			for _, current := range object.Fields {
				fields[current.Key] = true
			}
			for _, field := range resource.Fields {
				if field = strings.TrimSpace(field); field != "" && !fields[field] {
					object.Fields = append(object.Fields, definitionmodel.FieldSchema{Key: field})
					fields[field] = true
				}
			}
			byKey[key] = object
		}
	}
	objects := make([]definitionmodel.ObjectSchema, 0, len(byKey))
	for _, object := range byKey {
		objects = append(objects, object)
	}
	return objects
}
