package moduleassembly

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	identitycomposition "github.com/domainry/domainry-identity/internal/composition"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testAssemblyOptions(options identitycomposition.Options) identitycomposition.Options {
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return options
}
