package identity_test

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"

	"testing"

	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestIdentityServiceSearchRolesAcrossRequestedFieldsAndPaginates(t *testing.T) {
	store := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(store, nil).ForWorkspace(identitymodel.InstallationWorkspaceID)
	for _, role := range []identitymodel.IdentityRole{
		{ID: "admin", Key: "admin", Label: "Admin"},
		{ID: "finance-reviewer", Key: "finance_reviewer", Label: "Finance Reviewer"},
		{ID: "sales-manager", Key: "sales_manager", Label: "Sales Manager"},
	} {
		seedIdentityDirectoryRole(t, store, identitymodel.InstallationWorkspaceID, role)
	}

	byLabel, err := identity.SearchRoles(t.Context(), identitymodel.IdentityListQuery{
		PageSize: 10, Search: "reviewer", SearchFields: []string{"label", "key"},
	})

	if err != nil {
		t.Fatalf("search roles by label: %v", err)
	}
	if byLabel.Total != 1 || len(byLabel.Items) != 1 || byLabel.Items[0].ID != "finance-reviewer" {
		t.Fatalf("unexpected label search page: %#v", byLabel)
	}

	byKey, err := identity.SearchRoles(t.Context(), identitymodel.IdentityListQuery{
		PageSize: 10, Search: "sales_manager", SearchFields: []string{"label", "key"},
	})

	if err != nil {
		t.Fatalf("search roles by key: %v", err)
	}
	if byKey.Total != 1 || len(byKey.Items) != 1 || byKey.Items[0].ID != "sales-manager" {
		t.Fatalf("unexpected key search page: %#v", byKey)
	}

	page, err := identity.SearchRoles(t.Context(), identitymodel.IdentityListQuery{AfterID: "finance-reviewer", PageSize: 2})
	if err != nil {
		t.Fatalf("paginate roles: %v", err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].ID != "sales-manager" || page.PageSize != 2 || page.HasNext {
		t.Fatalf("unexpected pagination result: %#v", page)
	}

	if _, err := identity.SearchRoles(t.Context(), identitymodel.IdentityListQuery{SearchFields: []string{"permission_keys"}}); err == nil {
		t.Fatal("expected unsupported search field to be rejected")
	}
}
