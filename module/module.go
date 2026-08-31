// Package module exposes the stable in-process Identity module factory.
// Implementation details remain under internal/assembly/module.
package module

import moduleassembly "github.com/domainry/domainry-identity/internal/assembly/module"

const IdentityPortabilityProviderKey = moduleassembly.IdentityPortabilityProviderKey

type Options = moduleassembly.Options
type Factory = moduleassembly.Factory

func OptionsFromEnvironment() Options { return moduleassembly.OptionsFromEnvironment() }

func NewFactory(options Options) *Factory { return moduleassembly.NewFactory(options) }
