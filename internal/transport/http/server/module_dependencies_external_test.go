package httpserver_test

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testServerAssemblyOptions(values ...httpserver.ServerAssemblyOptions) httpserver.ServerAssemblyOptions {
	var options httpserver.ServerAssemblyOptions
	if len(values) > 0 {
		options = values[0]
	}
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return options
}
