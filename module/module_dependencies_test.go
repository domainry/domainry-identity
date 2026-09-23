package module_test

import (
	auditmodule "github.com/domainry/domainry-audit/module"
	identitymodule "github.com/domainry/domainry-identity/module"
	metadatamodule "github.com/domainry/domainry-metadata/module"
)

func testIdentityFactory(options identitymodule.Options) *identitymodule.Factory {
	options.AuditFactory = auditmodule.NewFactory(auditmodule.Options{})
	options.MetadataFactory = metadatamodule.NewFactory()
	return identitymodule.NewFactory(options)
}
