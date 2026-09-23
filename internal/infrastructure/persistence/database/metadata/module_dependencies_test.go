package metadata

import (
	"testing"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	metadatamoduleimpl "github.com/domainry/domainry-metadata/module"
)

func bindTestModuleDependencies(t *testing.T, store *database.IdentityStore) {
	t.Helper()
	metadataBinding, err := store.OpenMetadataModule(t.Context(), metadatamoduleimpl.NewFactory(), metadatasdk.ApplicationRef{InstallationID: "identity-metadata-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metadataBinding.Close(t.Context()) })
	auditBinding, err := auditmoduleimpl.NewFactory(auditmoduleimpl.Options{}).OpenModule(
		t.Context(), auditsdk.ApplicationRef{InstallationID: "identity-metadata-test"}, identityauditmodule.NewHost(store),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditBinding.Close(t.Context()) })
	if err := store.BindAudit(auditBinding); err != nil {
		t.Fatal(err)
	}
}
