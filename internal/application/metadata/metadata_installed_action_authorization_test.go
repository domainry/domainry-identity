package metadata

import (
	"strings"
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

func TestInstalledActionAuthorizationRequiresPersistedActionAndRoleGrantMatrix(t *testing.T) {
	installed := manifestmodel.ManifestSchema{
		Actions: []definitionmodel.ActionSchema{{
			Key: "booking.cancel",
		}},
		Roles: []identitymodel.RoleSchema{
			{Key: "member", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "booking.cancel")},
			{Key: "viewer"},
		},
	}
	persisted := installed
	if err := validateInstalledActionAuthorization(installed, persisted); err != nil {
		t.Fatalf("matching installed authorization was rejected: %v", err)
	}

	persisted.Actions = nil
	if err := validateInstalledActionAuthorization(installed, persisted); err == nil ||
		!strings.Contains(err.Error(), `installed Action "booking.cancel" was not persisted`) {
		t.Fatalf("missing persisted Action was not rejected: %v", err)
	}

	persisted = installed
	persisted.Roles = []identitymodel.RoleSchema{{Key: "member"}, {Key: "viewer"}}
	if err := validateInstalledActionAuthorization(installed, persisted); err == nil ||
		!strings.Contains(err.Error(), `persisted role "member" Action permission "booking.cancel"=false, want true`) {
		t.Fatalf("missing allowed-role grant was not rejected: %v", err)
	}

	persisted = installed
	persisted.Roles = []identitymodel.RoleSchema{
		{Key: "member", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "booking.cancel")},
		{Key: "viewer", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "booking.cancel")},
	}
	if err := validateInstalledActionAuthorization(installed, persisted); err == nil ||
		!strings.Contains(err.Error(), `persisted role "viewer" Action permission "booking.cancel"=true, want false`) {
		t.Fatalf("unallowed-role grant leak was not rejected: %v", err)
	}
}
