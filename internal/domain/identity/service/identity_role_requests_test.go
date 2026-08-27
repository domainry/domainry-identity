package service

import (
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityCreateRoleRequestNormalizesAndDeduplicatesRoles(t *testing.T) {
	repository, service := identityRolesFixture()
	created, err := service.CreateRoleRequest(t.Context(), identitymodel.IdentityRoleRequest{
		UserID: " user-1 ", RoleIDs: []string{"member", " member-id ", "viewer"},
		Provider: " oidc ", ProviderSubject: " subject ", Reason: " access needed ",
	})
	if err != nil || created.ID != "request-created" || created.UserID != "user-1" || created.Status != "pending" || len(created.RoleIDs) != 2 || created.RoleIDs[0] != "member-id" || created.RoleIDs[1] != "viewer-id" || created.Provider != "oidc" || created.ProviderSubject != "subject" || created.Reason != "access needed" {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	if len(repository.requests) != 1 {
		t.Fatalf("request not persisted: %#v", repository.requests)
	}
}

func TestIdentityCreateRoleRequestRejectsInvalidUsersAndRoles(t *testing.T) {
	tests := []struct {
		name    string
		request identitymodel.IdentityRoleRequest
		code    string
	}{
		{"missing user", identitymodel.IdentityRoleRequest{RoleIDs: []string{"member"}}, "backend.identity.user_required"},
		{"unknown user", identitymodel.IdentityRoleRequest{UserID: "missing", RoleIDs: []string{"member"}}, "auth.user_disabled"},
		{"disabled user", identitymodel.IdentityRoleRequest{UserID: "disabled-user", RoleIDs: []string{"member"}}, "auth.user_disabled"},
		{"unknown role", identitymodel.IdentityRoleRequest{UserID: "user-1", RoleIDs: []string{"missing"}}, "backend.identity.role_not_found"},
		{"privileged role", identitymodel.IdentityRoleRequest{UserID: "user-1", RoleIDs: []string{"admin"}}, "backend.identity.role_not_found"},
		{"no roles", identitymodel.IdentityRoleRequest{UserID: "user-1"}, "backend.identity.role_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, service := identityRolesFixture()
			if _, err := service.CreateRoleRequest(t.Context(), test.request); apperror.CodeOf(err) != test.code {
				t.Fatalf("expected %q, got %v", test.code, err)
			}
		})
	}
	repository, service := identityRolesFixture()
	repository.listUsersErr = errIdentityRolesRepository
	if _, err := service.CreateRoleRequest(t.Context(), identitymodel.IdentityRoleRequest{UserID: "user-1", RoleIDs: []string{"member"}}); err != errIdentityRolesRepository {
		t.Fatalf("expected user list error, got %v", err)
	}
	repository.listUsersErr = nil
	repository.listRolesErr = errIdentityRolesRepository
	if _, err := service.CreateRoleRequest(t.Context(), identitymodel.IdentityRoleRequest{UserID: "user-1", RoleIDs: []string{"member"}}); err != errIdentityRolesRepository {
		t.Fatalf("expected role list error, got %v", err)
	}
}

func TestIdentityApproveRoleRequestAssignsEveryRoleAndRecordsReview(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", RoleIDs: []string{"member-id", "viewer-id"}, Status: "pending"}}
	approved, err := service.ApproveRoleRequest(t.Context(), " request-1 ", " reviewer-1 ", " approved ")
	if err != nil || approved.Status != "approved" || approved.ReviewedBy != "reviewer-1" || approved.ReviewNote != "approved" || approved.ReviewedAt == "" || approved.UpdatedAt == "" || len(repository.assigned) != 2 || repository.updatedRequest.Status != "approved" {
		t.Fatalf("approved=%#v assigned=%#v persisted=%#v err=%v", approved, repository.assigned, repository.updatedRequest, err)
	}
}

func TestIdentityApproveHighRiskRoleRequestRequiresIndependentAuthorizedReviewer(t *testing.T) {
	for _, test := range []struct {
		name       string
		reviewerID string
		principal  []identitymodel.Principal
		code       string
	}{
		{name: "target self approval", reviewerID: "user-1", principal: []identitymodel.Principal{{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"admin"}}}}, code: "backend.identity.role_request_self_approval_denied"},
		{name: "maker checker", reviewerID: "maker", principal: []identitymodel.Principal{{Known: true, UserID: "maker", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"admin"}}}}, code: "backend.identity.role_request_maker_checker_required"},
		{name: "missing reviewer principal", reviewerID: "checker", code: "backend.identity.role_request_reviewer_principal_required"},
		{name: "wrong reviewer principal", reviewerID: "checker", principal: []identitymodel.Principal{{Known: true, UserID: "other", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"admin"}}}}, code: "backend.identity.role_request_reviewer_principal_required"},
		{name: "grant ceiling", reviewerID: "checker", principal: []identitymodel.Principal{{Known: true, UserID: "checker"}}, code: "backend.identity.role_grant_ceiling_exceeded"},
		{name: "approved", reviewerID: "checker", principal: []identitymodel.Principal{{Known: true, UserID: "checker", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"admin"}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, service := identityRolesFixture()
			service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
				Key: "admin", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly, RiskLevel: identitymodel.IdentityRoleRiskPrivileged,
			}})
			repository.requests = []identitymodel.IdentityRoleRequest{{
				ID: "request-1", UserID: "user-1", RequestedBy: "maker", RoleIDs: []string{"admin-id"}, Status: "pending",
			}}
			approved, err := service.ApproveRoleRequest(t.Context(), "request-1", test.reviewerID, "reviewed", test.principal...)
			if test.code != "" {
				if apperror.CodeOf(err) != test.code || len(repository.assigned) != 0 || repository.updatedRequest.Status != "" {
					t.Fatalf("approved=%#v assigned=%#v persisted=%#v err=%v", approved, repository.assigned, repository.updatedRequest, err)
				}
				return
			}
			if err != nil || approved.Status != "approved" || len(repository.assigned) != 1 {
				t.Fatalf("approved=%#v assigned=%#v err=%v", approved, repository.assigned, err)
			}
		})
	}
}

func TestIdentityApproveRoleRequestRejectsConflictingRolesWithinOneRequest(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly, ConflictRoleKeys: []string{"viewer"}},
		{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentRequestOnly},
	})
	repository.requests = []identitymodel.IdentityRoleRequest{{
		ID: "request-1", UserID: "user-1", RequestedBy: "maker", RoleIDs: []string{"member-id", "viewer-id"}, Status: "pending",
	}}
	if _, err := service.ApproveRoleRequest(t.Context(), "request-1", "checker", ""); apperror.CodeOf(err) != "backend.identity.role_conflict" {
		t.Fatalf("conflicting request error=%v", err)
	}
	if len(repository.assigned) != 0 || repository.updatedRequest.Status != "" {
		t.Fatalf("conflicting request partially persisted assignments=%#v request=%#v", repository.assigned, repository.updatedRequest)
	}
}

func TestIdentityApproveRoleRequestFailures(t *testing.T) {
	tests := []struct {
		name     string
		requests []identitymodel.IdentityRoleRequest
		code     string
	}{
		{"missing", nil, "backend.identity.role_request_not_found"},
		{"not pending", []identitymodel.IdentityRoleRequest{{ID: "request-1", Status: "approved"}}, "backend.identity.role_request_not_pending"},
		{"assignment fails", []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "missing", RoleIDs: []string{"member-id"}, Status: "pending"}}, "backend.identity.user_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, service := identityRolesFixture()
			repository.requests = test.requests
			if _, err := service.ApproveRoleRequest(t.Context(), "request-1", "reviewer", ""); apperror.CodeOf(err) != test.code {
				t.Fatalf("expected %q, got %v", test.code, err)
			}
		})
	}
	repository, service := identityRolesFixture()
	repository.listRequestsErr = errIdentityRolesRepository
	if _, err := service.ApproveRoleRequest(t.Context(), "request-1", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("expected repository error, got %v", err)
	}
	repository, service = identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", RoleIDs: []string{"member-id"}, Status: "pending"}}
	repository.updateRequestErr = errIdentityRolesRepository
	if _, err := service.ApproveRoleRequest(t.Context(), "request-1", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("expected update error, got %v", err)
	}
}

func TestIdentityRejectRoleRequest(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", Status: "pending"}}
	rejected, err := service.RejectRoleRequest(t.Context(), "request-1", " reviewer ", " denied ")
	if err != nil || rejected.Status != "rejected" || rejected.ReviewedBy != "reviewer" || rejected.ReviewNote != "denied" || repository.updatedRequest.Status != "rejected" {
		t.Fatalf("rejected=%#v persisted=%#v err=%v", rejected, repository.updatedRequest, err)
	}
	for _, request := range []identitymodel.IdentityRoleRequest{{ID: "other", Status: "pending"}, {ID: "request-1", Status: "approved"}} {
		repository, service = identityRolesFixture()
		repository.requests = []identitymodel.IdentityRoleRequest{request}
		_, err = service.RejectRoleRequest(t.Context(), "request-1", "reviewer", "")
		want := "backend.identity.role_request_not_found"
		if request.ID == "request-1" {
			want = "backend.identity.role_request_not_pending"
		}
		if apperror.CodeOf(err) != want {
			t.Fatalf("expected %q, got %v", want, err)
		}
	}
	repository, service = identityRolesFixture()
	repository.listRequestsErr = errIdentityRolesRepository
	if _, err := service.RejectRoleRequest(t.Context(), "request-1", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("expected lookup error, got %v", err)
	}
	repository, service = identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", Status: "pending"}}
	repository.updateRequestErr = errIdentityRolesRepository
	if _, err := service.RejectRoleRequest(t.Context(), "request-1", "reviewer", ""); err != errIdentityRolesRepository {
		t.Fatalf("expected update error, got %v", err)
	}
}

func TestIdentityRoleRequestLookupAndList(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.requests = []identitymodel.IdentityRoleRequest{{ID: "request-1", UserID: "user-1", Status: "pending"}, {ID: "request-2", UserID: "user-2", Status: "approved"}}
	requests, err := service.ListRoleRequests(t.Context(), " pending ", " user-1 ")
	if err != nil || len(requests) != 1 || requests[0].ID != "request-1" {
		t.Fatalf("requests=%#v err=%v", requests, err)
	}
	if _, found, err := service.roleRequestByID(t.Context(), " "); err != nil || found {
		t.Fatalf("empty lookup found=%v err=%v", found, err)
	}
	if request, found, err := service.roleRequestByID(t.Context(), "request-2"); err != nil || !found || request.ID != "request-2" {
		t.Fatalf("request=%#v found=%v err=%v", request, found, err)
	}
}
