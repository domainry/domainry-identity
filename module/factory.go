package module

import (
	"context"
	"fmt"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity-sdk/application"
	identitymanagement "github.com/domainry/domainry-identity-sdk/management"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	"github.com/domainry/domainry-identity/internal/assembly"
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

func (factory *Factory) Open(ctx context.Context, host identitysdk.Host) (identitysdk.Binding, error) {
	moduleHost, ok := host.(identitymodulehost.Host)
	if !ok {
		return nil, &identitysdk.Error{Code: "identity.module_host_capabilities_required"}
	}
	cfg, _, err := loadModuleConfig(factory.Options)
	if err != nil {
		return nil, err
	}
	application := moduleHost.Application()
	if !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return nil, &identitysdk.Error{Code: "identity.module_application_scope_required"}
	}
	// The embedding Runtime owns the application identity. It is the
	// authoritative token audience, avoiding a split trust scope between
	// Runtime IDENTITY_AUDIENCE and module-local environment configuration.
	cfg.AuthAudience = string(application.ApplicationKey)
	hostDatabase, err := moduleHost.IdentityDatabase(ctx)
	if err != nil {
		return nil, fmt.Errorf("open host Identity database: %w", err)
	}
	if hostDatabase.DB == nil || strings.TrimSpace(hostDatabase.Driver) == "" {
		return nil, &identitysdk.Error{Code: "identity.module_database_unavailable"}
	}
	if err := moduleHost.RegisterIdentityMigrations(ctx, []identitymodulehost.Migration{{
		Version: database.CurrentIdentitySchemaVersion,
		Up: func(migrationCtx context.Context, migrationDatabase identitymodulehost.Database) error {
			store, attachErr := database.AttachContext(migrationCtx, cfg, migrationDatabase.DB, migrationDatabase.Driver, migrationDatabase.Schema)
			if attachErr != nil {
				return attachErr
			}
			return store.EnsureSchema(migrationCtx)
		},
	}}); err != nil {
		return nil, fmt.Errorf("register Identity module migrations: %w", err)
	}
	store, err := database.AttachContext(ctx, cfg, hostDatabase.DB, hostDatabase.Driver, hostDatabase.Schema)
	if err != nil {
		return nil, err
	}
	identityRuntime, err := assembly.New(ctx, cfg, store, assembly.Options{Clock: moduleHost.Clock()})
	if err != nil {
		return nil, err
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
	managementSurface := &moduleManagementSurface{handler: managementServer.Routes()}
	for _, pattern := range managementServer.IdentityManagementRoutes() {
		managementSurface.routes = append(managementSurface.routes, identitymanagement.Route{Pattern: pattern})
	}
	return &moduleBinding{Binding: scopedBinding, runtime: identityRuntime, management: managementSurface}, nil
}

type moduleBinding struct {
	identitysdk.Binding
	runtime    *assembly.Core
	management identitymanagement.Surface
}

func (binding *moduleBinding) ManagementSurface() identitymanagement.Surface {
	if binding == nil {
		return nil
	}
	return binding.management
}

func (binding *moduleBinding) Close(ctx context.Context) error {
	if binding == nil || binding.runtime == nil {
		return nil
	}
	return binding.runtime.CloseContext(ctx)
}

var _ identitysdk.Factory = (*Factory)(nil)
var _ identitysdk.Binding = (*moduleBinding)(nil)
var _ identitymanagement.Provider = (*moduleBinding)(nil)
