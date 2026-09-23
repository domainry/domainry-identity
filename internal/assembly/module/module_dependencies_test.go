package moduleassembly

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	identityassembly "github.com/domainry/domainry-identity/internal/assembly"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testAssemblyOptions(options identityassembly.Options) identityassembly.Options {
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return options
}
