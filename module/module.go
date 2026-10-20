// Package module exposes the stable in-process Identity module factory.
// Implementation details remain under internal/assembly/module.
package module

import (
	"context"

	"github.com/domainry/domainry-foundation/schemaownership"
	identitysdkadapter "github.com/domainry/domainry-identity/internal/adapter/identitysdk"
	moduleassembly "github.com/domainry/domainry-identity/internal/assembly/module"
	credentialemail "github.com/domainry/domainry-identity/internal/domain/auth/contract/credentialemail"
	databaseschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
)

const IdentityPortabilityProviderKey = moduleassembly.IdentityPortabilityProviderKey

type Options = moduleassembly.Options
type Factory = moduleassembly.Factory
type CredentialEmailMessage = credentialemail.Message
type CredentialEmailDelivery = credentialemail.Delivery

const MigrationOwner = databaseschema.MigrationOwner

func SchemaOwnership() []schemaownership.Table { return databaseschema.SchemaOwnership() }
func OwnedTables() []string                    { return schemaownership.Names(SchemaOwnership()) }

func OptionsFromEnvironment() Options { return moduleassembly.OptionsFromEnvironment() }

func NewFactory(options Options) *Factory { return moduleassembly.NewFactory(options) }

// BeginPrincipalResolutionScope reuses authoritative Identity reads only within
// one synchronous host evaluation. Always call end before external IO/execution.
func BeginPrincipalResolutionScope(ctx context.Context) (context.Context, func()) {
	return identitysdkadapter.BeginPrincipalResolutionScope(ctx)
}

func BeginPrincipalReadScope(ctx context.Context) (context.Context, func() error) {
	return identitysdkadapter.BeginPrincipalReadScope(ctx)
}
