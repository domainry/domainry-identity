package httpserver

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testServerAssemblyOptions(values ...ServerAssemblyOptions) ServerAssemblyOptions {
	var options ServerAssemblyOptions
	if len(values) > 0 {
		options = values[0]
	}
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return options
}
