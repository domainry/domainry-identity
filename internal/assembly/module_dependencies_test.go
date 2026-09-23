package assembly

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testAssemblyOptions(options Options) Options {
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return options
}
