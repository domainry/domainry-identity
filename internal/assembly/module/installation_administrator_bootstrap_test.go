package moduleassembly

import (
	"errors"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	"github.com/domainry/domainry-identity/internal/assembly"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestInstallationAdministratorBootstrapRejectsZeroValueAuthStore(t *testing.T) {
	binding := &moduleBinding{runtime: &assembly.Core{
		IdentityStore: &identitypersistence.SQLIdentityStore{},
		Audit:         auditapplication.NewAuditApplicationService(nil),
	}}

	_, err := binding.BootstrapInstallationAdministratorV1(t.Context(), identitymodulehost.InstallationAdministratorBootstrapRequest{}, identitymodulehost.Transaction{})
	var sdkErr *identitysdk.Error
	if !errors.As(err, &sdkErr) || sdkErr.Code != "identity.installation_administrator_bootstrap_unavailable" {
		t.Fatalf("BootstrapInstallationAdministratorV1() error = %v, want identity.installation_administrator_bootstrap_unavailable", err)
	}
}
