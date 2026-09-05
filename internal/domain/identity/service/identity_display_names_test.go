package service

import (
	"context"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type identityDisplayNameRepository struct {
	identityrepository.IdentityRepository
	userScope identitymodel.IdentityDataScopeFilter
	orgScope  identitymodel.IdentityDataScopeFilter
}

func (r *identityDisplayNameRepository) ListIdentityUsersWithinDataScope(_ context.Context, _ string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityUser, error) {
	r.userScope = scope
	return []identitymodel.IdentityUser{{ID: "user-2", Name: "Ada"}}, nil
}

func (r *identityDisplayNameRepository) GetIdentityUserWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityUser, bool, error) {
	return identitymodel.IdentityUser{}, false, nil
}

func (r *identityDisplayNameRepository) ListIdentityOrganizationUnitsWithinDataScope(_ context.Context, _ string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityOrganizationUnit, error) {
	r.orgScope = scope
	return []identitymodel.IdentityOrganizationUnit{{ID: "org-2", Name: "Engineering"}}, nil
}

func (r *identityDisplayNameRepository) GetIdentityOrganizationUnitWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityOrganizationUnit, bool, error) {
	return identitymodel.IdentityOrganizationUnit{}, false, nil
}

func TestResolveProjectionDisplayNamesUsesStorageIDPredicates(t *testing.T) {
	repository := &identityDisplayNameRepository{}
	service, err := NewIdentityDomainService(repository, nil).ForWorkspace("workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	users, organizations, err := service.ResolveProjectionDisplayNames(t.Context(), []string{"user-2", "user-1"}, []string{"org-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Name != "Ada" || len(organizations) != 1 || organizations[0].Name != "Engineering" {
		t.Fatalf("resolved users=%#v organizations=%#v", users, organizations)
	}
	if !reflect.DeepEqual(repository.userScope.OwnerUserIDs, []string{"user-2", "user-1"}) || repository.userScope.Unrestricted {
		t.Fatalf("user storage scope=%#v", repository.userScope)
	}
	if !reflect.DeepEqual(repository.orgScope.OwnerOrgIDs, []string{"org-2"}) || repository.orgScope.Unrestricted {
		t.Fatalf("organization storage scope=%#v", repository.orgScope)
	}
}
