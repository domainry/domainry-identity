package identity

import (
	"encoding/base64"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestStoreOrganizationPurposePermissionUsesCanonicalHierarchyScopes(t *testing.T) {
	permission := identitycontract.IdentityStoreOrganizationDeliveryCreatePermission
	principal := func(scope identitymodel.IdentityDataScope) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, UserID: "operator", OrgID: "company-a", OrgScopeIDs: []string{"company-a", "store-a"},
			SupportOrgScopeIDs: []string{"company-b", "store-b"},
			Role:               identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(scope, permission)},
		}
	}
	for _, test := range []struct {
		name string
		role identitymodel.Principal
		id   string
		want bool
	}{
		{name: "all", role: principal(identitymodel.IdentityDataScopeAll), id: "any", want: true},
		{name: "org", role: principal(identitymodel.IdentityDataScopeOrg), id: "company-a", want: true},
		{name: "org denied", role: principal(identitymodel.IdentityDataScopeOrg), id: "store-a"},
		{name: "org child", role: principal(identitymodel.IdentityDataScopeOrgChild), id: "store-a", want: true},
		{name: "target org", role: principal(identitymodel.IdentityDataScopeTargetOrg), id: "store-b", want: true},
		{name: "target org denied", role: principal(identitymodel.IdentityDataScopeTargetOrg), id: "store-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := storeOrganizationScopeAllows(test.role, permission, test.id); got != test.want {
				t.Fatalf("scope=%v want=%v", got, test.want)
			}
		})
	}
}

func TestStoreOrganizationPurposePermissionDoesNotAliasGenericOrganizationCRUD(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, identitycontract.IdentityStoreOrganizationDeliveryCreatePermission)}
	for _, generic := range []string{"identity.organization_units.create", "identity.organization_units.update", "identity.organization_units.get", "identity.organization_units.list"} {
		if identitycontract.IdentityRoleHasPermissionKey(role, generic) {
			t.Fatalf("purpose-specific grant aliased %q", generic)
		}
	}
}

func TestStoreOrganizationPageSizeUsesDefaultAndEnforcesMaximum(t *testing.T) {
	if got, err := normalizeStoreOrganizationPageSize(0); err != nil || got != IdentityStoreOrganizationDefaultPageSize {
		t.Fatalf("default page size=%d err=%v", got, err)
	}
	if got, err := normalizeStoreOrganizationPageSize(IdentityStoreOrganizationMaxPageSize); err != nil || got != IdentityStoreOrganizationMaxPageSize {
		t.Fatalf("maximum page size=%d err=%v", got, err)
	}
	for _, invalid := range []int{-1, IdentityStoreOrganizationMaxPageSize + 1} {
		if _, err := normalizeStoreOrganizationPageSize(invalid); apperror.CodeOf(err) != "backend.identity.store_organization_page_size_invalid" {
			t.Fatalf("page size %d error=%v", invalid, err)
		}
	}
}

func TestStoreOrganizationCursorIsOpaqueStrictAndRoundTrips(t *testing.T) {
	cursor, err := encodeStoreOrganizationCursor("store-002")
	if err != nil {
		t.Fatal(err)
	}
	if cursor == "store-002" {
		t.Fatal("cursor exposed the raw store ID")
	}
	afterID, err := decodeStoreOrganizationCursor(cursor)
	if err != nil || afterID != "store-002" {
		t.Fatalf("decoded after_id=%q err=%v", afterID, err)
	}
	if afterID, err := decodeStoreOrganizationCursor(""); err != nil || afterID != "" {
		t.Fatalf("empty cursor after_id=%q err=%v", afterID, err)
	}
	invalid := []string{
		"not-base64***",
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"after_id":"store-002"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"after_id":""}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"after_id":"store-002","scope":"all"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"after_id":"store-002"} trailing`)),
	}
	for _, value := range invalid {
		if _, err := decodeStoreOrganizationCursor(value); apperror.CodeOf(err) != "backend.identity.store_organization_cursor_invalid" {
			t.Fatalf("cursor %q error=%v", value, err)
		}
	}
}
