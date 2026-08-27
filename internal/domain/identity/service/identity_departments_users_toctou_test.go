package service

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestUpsertDepartmentRechecksChangedRepositorySnapshot(t *testing.T) {
	parentID := "parent"
	parent := identitymodel.IdentityDepartment{ID: parentID, Name: "Parent", Path: "/parent"}
	department := identitymodel.IdentityDepartment{ID: "child", Name: "Child", ParentID: &parentID}
	for _, test := range []struct {
		name   string
		second []identitymodel.IdentityDepartment
	}{
		{name: "parent removed"},
		{name: "cycle introduced", second: []identitymodel.IdentityDepartment{
			{ID: parentID, Name: "Parent", ParentID: identityStringPointer("child"), Path: "/parent"},
			{ID: "child", Name: "Old Child", Path: "/child"},
		}},
		{name: "duplicate name introduced", second: []identitymodel.IdentityDepartment{
			parent, {ID: "sibling", Name: " child ", ParentID: &parentID, Path: "/parent/sibling"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityDepartmentUserRepository{departmentLists: [][]identitymodel.IdentityDepartment{{parent}, test.second}}
			if err := NewIdentityDomainService(repository, nil).UpsertDepartment(t.Context(), department); err == nil {
				t.Fatal("changed department snapshot was accepted")
			}
		})
	}
}

func TestUpsertUserRechecksAccountEmailAndUsesSingleAccountWrite(t *testing.T) {
	user := identitymodel.IdentityUser{ID: "user", Name: " User ", Email: " USER@example.com ", Phone: " 123 "}
	repository := &identityDepartmentUserRepository{userLists: [][]identitymodel.IdentityUser{
		nil, {{ID: "other", Email: "user@example.com"}},
	}}
	if err := NewIdentityDomainService(repository, nil).UpsertUser(t.Context(), user); err == nil {
		t.Fatal("email introduced between validation and write was accepted")
	}

	repository = &identityDepartmentUserRepository{userLists: [][]identitymodel.IdentityUser{nil, nil}}
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
