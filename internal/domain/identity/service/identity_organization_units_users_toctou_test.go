package service

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestUpsertOrganizationUnitRechecksChangedRepositorySnapshot(t *testing.T) {
	parentID := "parent"
	parent := identitymodel.IdentityOrganizationUnit{OrganizationUnitID: parentID, Code: "PARENT", Name: "Parent", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Path: "/parent"}
	organizationUnit := identitymodel.IdentityOrganizationUnit{OrganizationUnitID: "child", Code: "CHILD", Name: "Child", NodeType: identitymodel.IdentityOrganizationUnitDepartment, ParentID: &parentID}
	for _, test := range []struct {
		name   string
		second []identitymodel.IdentityOrganizationUnit
	}{
		{name: "parent removed"},
		{name: "cycle introduced", second: []identitymodel.IdentityOrganizationUnit{
			{OrganizationUnitID: parentID, Name: "Parent", ParentID: identityStringPointer("child"), Path: "/parent"},
			{OrganizationUnitID: "child", Name: "Old Child", Path: "/child"},
		}},
		{name: "duplicate name introduced", second: []identitymodel.IdentityOrganizationUnit{
			parent, {OrganizationUnitID: "sibling", Name: " child ", ParentID: &parentID, Path: "/parent/sibling"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityOrganizationUnitUserRepository{organizationUnitLists: [][]identitymodel.IdentityOrganizationUnit{{parent}, test.second}}
			if err := NewIdentityDomainService(repository, nil).UpsertOrganizationUnit(t.Context(), organizationUnit); err == nil {
				t.Fatal("changed organizationUnit snapshot was accepted")
			}
		})
	}
}

func TestUpsertUserRechecksAccountEmailAndUsesSingleAccountWrite(t *testing.T) {
	user := identitymodel.IdentityUser{UserID: "user", Name: " User ", Email: " USER@example.com ", Phone: " 123 "}
	repository := &identityOrganizationUnitUserRepository{userLists: [][]identitymodel.IdentityUser{
		nil, {{UserID: "other", Email: "user@example.com"}},
	}}
	if err := NewIdentityDomainService(repository, nil).UpsertUser(t.Context(), user); err == nil {
		t.Fatal("email introduced between validation and write was accepted")
	}

	repository = &identityOrganizationUnitUserRepository{userLists: [][]identitymodel.IdentityUser{nil, nil}}
	if err := NewIdentityDomainService(repository, nil).UpsertUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if len(repository.users) != 1 {
		t.Fatalf("account write count=%d", len(repository.users))
	}
	got := repository.users[0]
	if got.Name != "User" || got.Email != "user@example.com" || got.Phone != "123" {
		t.Fatalf("account normalization=%#v", got)
	}
}

func identityStringPointer(value string) *string { return &value }
