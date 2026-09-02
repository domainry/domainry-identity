package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type directoryProjectionRepository struct {
	*identityScopedRepository
	bindings map[string][]identitymodel.IdentityProfileBinding
	fail     string
	err      error
}

type directoryProjectionFactsRepository struct {
	*directoryProjectionRepository
	facts identitymodel.IdentityUserDirectoryFacts
	err   error
}

func (r *directoryProjectionFactsRepository) ListIdentityUserDirectoryFacts(context.Context, string, []string) (identitymodel.IdentityUserDirectoryFacts, error) {
	return r.facts, r.err
}

func (r *directoryProjectionRepository) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	if r.fail == "users" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityUsers(ctx, workspaceID)
}

func (r *directoryProjectionRepository) ListIdentityOrganizationUnits(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	if r.fail == "organizationUnits" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityOrganizationUnits(ctx, workspaceID)
}

func (r *directoryProjectionRepository) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.fail == "assignments" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityUserRoleAssignments(ctx, workspaceID, userID)
}

func (r *directoryProjectionRepository) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	if r.fail == "roles" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityRoles(ctx, workspaceID)
}

func (r *directoryProjectionRepository) ListIdentityProfileBindingsByUser(_ context.Context, _, userID string) ([]identitymodel.IdentityProfileBinding, error) {
	if r.fail == "bindings" {
		return nil, r.err
	}
	return r.bindings[userID], nil
}

func directoryProjectionFixture() (*IdentityApplicationService, *directoryProjectionRepository) {
	base := &identityScopedRepository{
		users: []identitymodel.IdentityUser{
			{ID: "user-1", Name: "Alice", Status: identitymodel.IdentityStatusActive},
			{ID: "user-2", Name: "Bob", Status: identitymodel.IdentityStatusDisabled},
		},
		roles: []identitymodel.IdentityRole{
			{ID: "role-b", Key: "viewer", Label: "Viewer"},
			{ID: "role-a", Key: "admin", Label: "Admin"},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user-1", RoleID: "role-b", Source: "request", Status: "active"},
			{UserID: "user-1", RoleID: "role-a", Source: "manual", Status: "active"},
		},
	}
	repository := &directoryProjectionRepository{
		identityScopedRepository: base,
		bindings: map[string][]identitymodel.IdentityProfileBinding{
			"user-1": {
				{BindingKey: "member", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive},
				{BindingKey: "old", ProfileID: "old-1", IdentityUserID: "user-1", Status: identitymodel.IdentityProfileBindingUnlinked},
			},
		},
	}
	return NewIdentityApplicationService(repository, nil), repository
}

func TestSearchUserDirectoryProjectsRolesSecurityAndIdentityBadges(t *testing.T) {
	service, _ := directoryProjectionFixture()
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	page, err := service.SearchUserDirectory(ctx, identitymodel.IdentityListQuery{PageSize: 1}, func(_ context.Context, workspaceID, userID string) (IdentityUserDirectorySecuritySummary, error) {
		if workspaceID != "workspace-primary" || userID != "user-1" {
			t.Fatalf("unexpected security lookup %q/%q", workspaceID, userID)
		}
		return IdentityUserDirectorySecuritySummary{MFAEnabled: true, Locked: true, ActiveSessions: 2, LastLoginAt: "now"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || !page.HasNext || len(page.Items) != 1 {
		t.Fatalf("unexpected page: %#v", page)
	}
	entry := page.Items[0]
	if entry.User.ID != "user-1" || len(entry.Roles) != 2 || entry.Roles[0].Key != "admin" ||
		len(entry.IdentityBadges) != 1 || entry.IdentityBadges[0].Kind != "business_profile" ||
		!entry.Security.MFAEnabled || entry.Security.ActiveSessions != 2 {
		t.Fatalf("unexpected directory entry: %#v", entry)
	}
}

func TestSearchUserDirectoryFailureBoundaries(t *testing.T) {
	service, repository := directoryProjectionFixture()
	validContext := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	readerFailure := errors.New("security unavailable")
	if _, err := service.SearchUserDirectory(t.Context(), identitymodel.IdentityListQuery{}, func(context.Context, string, string) (IdentityUserDirectorySecuritySummary, error) {
		return IdentityUserDirectorySecuritySummary{}, nil
	}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("expected workspace error, got %v", err)
	}
	if _, err := service.SearchUserDirectory(validContext, identitymodel.IdentityListQuery{}, nil); apperror.CodeOf(err) != "backend.identity.user_directory_security_unavailable" {
		t.Fatalf("expected security capability error, got %v", err)
	}
	for _, failure := range []string{"users", "assignments", "roles", "bindings"} {
		repository.fail, repository.err = failure, errors.New(failure)
		_, err := service.SearchUserDirectory(validContext, identitymodel.IdentityListQuery{}, func(context.Context, string, string) (IdentityUserDirectorySecuritySummary, error) {
			return IdentityUserDirectorySecuritySummary{}, nil
		})
		if !errors.Is(err, repository.err) {
			t.Fatalf("%s: expected repository error, got %v", failure, err)
		}
	}
	repository.fail = ""
	_, err := service.SearchUserDirectory(validContext, identitymodel.IdentityListQuery{}, func(context.Context, string, string) (IdentityUserDirectorySecuritySummary, error) {
		return IdentityUserDirectorySecuritySummary{}, readerFailure
	})
	if !errors.Is(err, readerFailure) {
		t.Fatalf("expected security reader error, got %v", err)
	}
}

func TestSearchUserDirectoryWithoutBusinessProfiles(t *testing.T) {
	repository := &identityScopedRepository{users: []identitymodel.IdentityUser{{ID: "user", Name: "User"}}}
	service := NewIdentityApplicationService(repository, nil)
	page, err := service.SearchUserDirectory(requestcontext.WithWorkspaceID(t.Context(), "workspace-primary"), identitymodel.IdentityListQuery{}, func(context.Context, string, string) (IdentityUserDirectorySecuritySummary, error) {
		return IdentityUserDirectorySecuritySummary{}, nil
	})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].IdentityBadges) != 0 {
		t.Fatalf("unexpected directory projection: %#v, %v", page, err)
	}
}

func TestSearchUserDirectoryBatchUsesFactsCapabilityAndValidatesReader(t *testing.T) {
	service, base := directoryProjectionFixture()
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	if _, err := service.SearchUserDirectoryBatch(ctx, identitymodel.IdentityListQuery{}, nil); apperror.CodeOf(err) != "backend.identity.user_directory_security_unavailable" {
		t.Fatalf("nil batch reader error=%v", err)
	}
	factsRepository := &directoryProjectionFactsRepository{
		directoryProjectionRepository: base,
		facts: identitymodel.IdentityUserDirectoryFacts{
			RoleAssignments: base.assignments,
			ProfileBindings: []identitymodel.IdentityProfileBinding{{
				IdentityUserID: "user-1", BindingKey: "member", ProfileID: "member-1", Status: identitymodel.IdentityProfileBindingActive,
			}},
		},
	}
	factsService := NewIdentityApplicationService(factsRepository, nil)
	page, err := factsService.SearchUserDirectoryBatch(ctx, identitymodel.IdentityListQuery{}, func(_ context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserDirectorySecuritySummary, error) {
		if workspaceID != "workspace-primary" || len(userIDs) != 2 {
			t.Fatalf("workspace=%q users=%v", workspaceID, userIDs)
		}
		return map[string]IdentityUserDirectorySecuritySummary{"user-1": {MFAEnabled: true}}, nil
	})
	if err != nil || len(page.Items) != 2 || !page.Items[0].Security.MFAEnabled {
		t.Fatalf("facts page=%#v err=%v", page, err)
	}
	factsRepository.err = errors.New("facts")
	if _, err := factsService.SearchUserDirectoryBatch(ctx, identitymodel.IdentityListQuery{}, func(context.Context, string, []string) (map[string]IdentityUserDirectorySecuritySummary, error) {
		return nil, nil
	}); !errors.Is(err, factsRepository.err) {
		t.Fatalf("facts error=%v", err)
	}
}
