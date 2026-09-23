package identity_test

import (
	"testing"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func bindTestAuditModule(t *testing.T, store *database.IdentityStore, identityStore *identitypersistence.SQLIdentityStore) {
	t.Helper()
	binding, err := auditmoduleimpl.NewFactory(auditmoduleimpl.Options{}).OpenModule(
		t.Context(), auditsdk.ApplicationRef{InstallationID: "identity-integration-test"}, identityauditmodule.NewHost(store),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = binding.Close(t.Context()) })
	if err := store.BindAudit(binding); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.BindAudit(binding); err != nil {
		t.Fatal(err)
	}
}
