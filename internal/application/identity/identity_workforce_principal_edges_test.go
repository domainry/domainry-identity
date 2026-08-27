package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestWorkforcePrincipalReadBoundaries(t *testing.T) {
	service, repository, admin, ctx := workforceProjectionFixture()
	if scope := identityWorkforceReadScope(identitymodel.Principal{Role: identitymodel.RoleSchema{RecordScope: "owned_records"}}); scope != "owned_records" {
		t.Fatalf("legacy scope=%q", scope)
	}
	if scope := identityWorkforceReadScope(admin); scope != "all_records" {
		t.Fatalf("admin scope=%q", scope)
	}
	if _, _, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("authorization err=%v", err)
	}
	if _, found, err := service.GetWorkforceProfileForPrincipal(ctx, "missing", admin); err != nil || found {
		t.Fatalf("missing found=%v err=%v", found, err)
	}
	repository.fail, repository.err = "get_workforce", errors.New("get workforce")
	if _, _, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", admin); !errors.Is(err, repository.err) {
		t.Fatalf("get err=%v", err)
	}
	repository.fail = ""
	denied := admin
	denied.UserID = "other"
	denied.Role = identitymodel.RoleSchema{RecordScope: "owned_records"}
	if _, found, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", denied); err != nil || found {
		t.Fatalf("denied found=%v err=%v", found, err)
	}
	repository.fail, repository.err = "workforce_assignments", errors.New("assignments")
	if _, _, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", admin); !errors.Is(err, repository.err) {
		t.Fatalf("assignment err=%v", err)
	}
	repository.fail, repository.err = "departments", errors.New("departments")
	if _, _, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", admin); !errors.Is(err, repository.err) {
		t.Fatalf("department err=%v", err)
	}
	repository.fail = ""
	if profile, found, err := service.GetWorkforceProfileForPrincipal(ctx, "profile-a", admin); err != nil || !found || profile.ID != "profile-a" {
		t.Fatalf("profile=%+v found=%v err=%v", profile, found, err)
	}
}

func TestSearchWorkforceProfilesForPrincipalScopeBoundaries(t *testing.T) {
	service, _, admin, ctx := workforceProjectionFixture()
	if _, err := service.SearchWorkforceProfilesForPrincipal(ctx, identitymodel.IdentityListQuery{}, identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("authorization err=%v", err)
	}
	if _, err := service.SearchWorkforceProfilesForPrincipal(context.Background(), identitymodel.IdentityListQuery{}, admin); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("context scope err=%v", err)
	}
	if _, err := service.SearchWorkforceProfilesForPrincipal(ctx, identitymodel.IdentityListQuery{}, admin); err != nil {
		t.Fatalf("search err=%v", err)
	}
}

func TestWorkforceDetailForPrincipalBoundaries(t *testing.T) {
	service, repository, admin, ctx := workforceProjectionFixture()
	if _, found, err := service.GetWorkforceDetailForPrincipal(ctx, "missing", admin); err != nil || found {
		t.Fatalf("missing found=%v err=%v", found, err)
	}
	repository.fail, repository.err = "get_workforce", errors.New("get")
	if _, _, err := service.GetWorkforceDetailForPrincipal(ctx, "profile-a", admin); !errors.Is(err, repository.err) {
		t.Fatalf("get err=%v", err)
	}
	repository.fail = ""
	detail, found, err := service.GetWorkforceDetailForPrincipal(ctx, "profile-a", admin)
	if err != nil || !found || detail.Profile.ID != "profile-a" || detail.Account.ID != "user-a" {
		t.Fatalf("detail=%+v found=%v err=%v", detail, found, err)
	}
	if _, err := service.canReadWorkforceProfile(context.Background(), repository.workforce[0], admin); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("context scope err=%v", err)
	}
}
