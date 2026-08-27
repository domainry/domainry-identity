package identity

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

func TestManifestIdentitySeedIncludesProjectNavigation(t *testing.T) {
	seed := FromManifest(manifestmodel.ManifestSchema{IdentityBootstrap: &identitymodel.ManifestIdentityBootstrapSchema{
		Version:   "1",
		Menus:     []identitymodel.IdentityMenu{{ID: "business_floor", Key: "business.floor", Route: "business.floor", Status: identitymodel.IdentityStatusActive}},
		RoleMenus: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "store_manager", MenuID: "business_floor"}},
	}})
	foundMenu, foundBinding := false, false
	for _, menu := range seed.Menus {
		foundMenu = foundMenu || menu.ID == "business_floor"
	}
	for _, binding := range seed.RoleMenus {
		foundBinding = foundBinding || (binding.RoleID == "store_manager" && binding.MenuID == "business_floor")
	}
	if !foundMenu || !foundBinding {
		t.Fatalf("menu=%v binding=%v", foundMenu, foundBinding)
	}
}
