package service

import (
	"context"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func identityActorCanManageRoleTarget(actor identitymodel.Principal, target identitymodel.IdentityUser) bool {
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return false
	}
	if actor.UserID == target.ID {
		return true
	}
	scopes := actor.EffectiveRecordScopes
	if len(scopes) == 0 {
		scopes = identityEffectiveRecordScopes(actor.Role.RecordScope)
	}
	for _, scope := range scopes {
		switch scope {
		case "all_records":
			return true
		case "organization":
			if actor.OrgID != "" && actor.OrgID == target.OrgID {
				return true
			}
		case "organization_and_children":
			if identityStringSliceContains(actor.OrgScopeIDs, strings.TrimSpace(target.OrgID)) {
				return true
			}
		case "self_and_subordinates":
			if identityStringSliceContains(actor.ReportingScopeUserIDs, strings.TrimSpace(target.ID)) {
				return true
			}
		}
	}
	return false
}

func (s *IdentityDomainService) listRequestableRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	out := []identitymodel.IdentityRole{}
	for _, role := range roles {
		definition, published := s.publishedRoleDefinition(role)
		if !published || definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged ||
			(s.identityPrivilegedAutoAssignableRole(role) && definition.AssignmentMode != identitymodel.IdentityRoleAssignmentRequestOnly) {
			continue
		}
		out = append(out, role)
	}
	return out, nil
}

func (s *IdentityDomainService) ListRequestableRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	return s.listRequestableRoles(ctx)
}

func (s *IdentityDomainService) CreateRoleRequest(ctx context.Context, request identitymodel.IdentityRoleRequest) (identitymodel.IdentityRoleRequest, error) {
	request.UserID = strings.TrimSpace(request.UserID)
	if request.UserID == "" {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.user_required")
	}
	user, ok, err := s.userByID(ctx, request.UserID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return identitymodel.IdentityRoleRequest{}, forbidden("auth.user_disabled")
	}
	assignableRoles, err := s.listRequestableRoles(ctx)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	assignable := map[string]identitymodel.IdentityRole{}
	for _, role := range assignableRoles {
		assignable[role.ID] = role
		assignable[role.Key] = role
	}
	roleIDs := []string{}
	seen := map[string]bool{}
	for _, roleID := range request.RoleIDs {
		roleID = strings.TrimSpace(roleID)
		role, ok := assignable[roleID]
		if !ok {
			return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_not_found", "role", roleID)
		}
		if seen[role.ID] {
			continue
		}
		seen[role.ID] = true
		roleIDs = append(roleIDs, role.ID)
	}
	if len(roleIDs) == 0 {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_required")
	}
	request.RoleIDs = roleIDs
	request.RequestedBy = valueOrDefault(strings.TrimSpace(request.RequestedBy), request.UserID)
	request.Provider = strings.TrimSpace(request.Provider)
	request.ProviderSubject = strings.TrimSpace(request.ProviderSubject)
	request.Status = valueOrDefault(strings.TrimSpace(request.Status), "pending")
	request.Reason = strings.TrimSpace(request.Reason)
	return s.repo.CreateIdentityRoleRequest(ctx, s.workspace, request)
}

func (s *IdentityDomainService) ListRoleRequests(ctx context.Context, status string, userID string) ([]identitymodel.IdentityRoleRequest, error) {
	return s.repo.ListIdentityRoleRequests(ctx, s.workspace, strings.TrimSpace(status), strings.TrimSpace(userID))
}

func (s *IdentityDomainService) ApproveRoleRequest(ctx context.Context, requestID string, reviewerID string, note string, reviewer ...identitymodel.Principal) (identitymodel.IdentityRoleRequest, error) {
	request, ok, err := s.roleRequestByID(ctx, requestID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if !ok {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_request_not_found")
	}
	if request.Status != "pending" {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_request_not_pending")
	}
	reviewerID = strings.TrimSpace(reviewerID)
	if reviewerID == "" || reviewerID == strings.TrimSpace(request.UserID) {
		return identitymodel.IdentityRoleRequest{}, forbidden("backend.identity.role_request_self_approval_denied")
	}
	assignments := make([]identitymodel.IdentityUserRoleAssignment, 0, len(request.RoleIDs))
	definitionsByRoleID := map[string]identitymodel.RoleSchema{}
	for _, roleID := range request.RoleIDs {
		role, found, err := s.roleByID(ctx, roleID)
		if err != nil {
			return identitymodel.IdentityRoleRequest{}, err
		}
		if !found {
			return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_not_found", "role", roleID)
		}
		definition, published := s.publishedRoleDefinition(role)
		if !published {
			definition = identitymodel.RoleSchema{Key: valueOrDefault(role.Key, role.ID), Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual}
		}
		if definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged {
			return identitymodel.IdentityRoleRequest{}, forbidden("backend.identity.system_managed_role_assignment_denied")
		}
		highRisk := definition.RiskLevel == identitymodel.IdentityRoleRiskElevated || definition.RiskLevel == identitymodel.IdentityRoleRiskPrivileged
		if highRisk {
			if reviewerID == strings.TrimSpace(request.RequestedBy) {
				return identitymodel.IdentityRoleRequest{}, forbidden("backend.identity.role_request_maker_checker_required")
			}
			if len(reviewer) == 0 || !reviewer[0].Known || strings.TrimSpace(reviewer[0].UserID) != reviewerID {
				return identitymodel.IdentityRoleRequest{}, forbidden("backend.identity.role_request_reviewer_principal_required")
			}
			if !identityStringSliceContains(reviewer[0].Role.GrantableRoleKeys, "*") &&
				!identityStringSliceContains(reviewer[0].Role.GrantableRoleKeys, definition.Key) {
				return identitymodel.IdentityRoleRequest{}, forbidden("backend.identity.role_grant_ceiling_exceeded")
			}
		}
		assignment := identitymodel.IdentityUserRoleAssignment{UserID: request.UserID, RoleID: roleID, Source: "governance_request", Status: "active", GrantedBy: reviewerID, GrantReason: request.Reason}
		issues, validateErr := s.validation.ValidateRoleAssignmentConfiguration(ctx, assignment)
		if validateErr != nil {
			return identitymodel.IdentityRoleRequest{}, validateErr
		}
		if validateErr = s.validation.FirstConfigurationError(issues); validateErr != nil {
			return identitymodel.IdentityRoleRequest{}, validateErr
		}
		if err := s.validateRoleEligibilityWithoutConflicts(ctx, assignment, definition, true); err != nil {
			return identitymodel.IdentityRoleRequest{}, err
		}
		assignments = append(assignments, assignment)
		definitionsByRoleID[roleID] = definition
	}
	currentAssignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, "")
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	allRoles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	for _, role := range allRoles {
		if _, exists := definitionsByRoleID[role.ID]; exists {
			continue
		}
		if definition, published := s.publishedRoleDefinition(role); published {
			definitionsByRoleID[role.ID] = definition
		}
	}
	final := make(map[string]identitymodel.IdentityUserRoleAssignment, len(currentAssignments)+len(assignments))
	for _, assignment := range currentAssignments {
		final[identityEntitlementAssignmentKey(assignment.UserID, assignment.RoleID)] = assignment
	}
	for _, assignment := range assignments {
		final[identityEntitlementAssignmentKey(assignment.UserID, assignment.RoleID)] = assignment
	}
	if err := validateIdentityEntitlementFinalState(final, definitionsByRoleID, time.Now()); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	request.Status = "approved"
	request.ReviewedBy = reviewerID
	request.ReviewedAt = now
	request.ReviewNote = strings.TrimSpace(note)
	request.UpdatedAt = now
	decisionRepository, ok := s.repo.(identityrepository.IdentityRoleRequestDecisionRepository)
	if !ok {
		return identitymodel.IdentityRoleRequest{}, internalError("role request atomic decision repository unavailable", nil)
	}
	if err := decisionRepository.ApplyIdentityRoleRequestDecision(ctx, s.workspace, request, assignments, "pending"); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return request, nil
}

func (s *IdentityDomainService) RejectRoleRequest(ctx context.Context, requestID string, reviewerID string, note string) (identitymodel.IdentityRoleRequest, error) {
	request, ok, err := s.roleRequestByID(ctx, requestID)
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	if !ok {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_request_not_found")
	}
	if request.Status != "pending" {
		return identitymodel.IdentityRoleRequest{}, badRequest("backend.identity.role_request_not_pending")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	request.Status = "rejected"
	request.ReviewedBy = strings.TrimSpace(reviewerID)
	request.ReviewedAt = now
	request.ReviewNote = strings.TrimSpace(note)
	request.UpdatedAt = now
	decisionRepository, ok := s.repo.(identityrepository.IdentityRoleRequestDecisionRepository)
	if !ok {
		return identitymodel.IdentityRoleRequest{}, internalError("role request atomic decision repository unavailable", nil)
	}
	if err := decisionRepository.ApplyIdentityRoleRequestDecision(ctx, s.workspace, request, nil, "pending"); err != nil {
		return identitymodel.IdentityRoleRequest{}, err
	}
	return request, nil
}

func (s *IdentityDomainService) roleRequestByID(ctx context.Context, requestID string) (identitymodel.IdentityRoleRequest, bool, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return identitymodel.IdentityRoleRequest{}, false, nil
	}
	requests, err := s.repo.ListIdentityRoleRequests(ctx, s.workspace, "", "")
	if err != nil {
		return identitymodel.IdentityRoleRequest{}, false, err
	}
	for _, request := range requests {
		if request.ID == requestID {
			return request, true, nil
		}
	}
	return identitymodel.IdentityRoleRequest{}, false, nil
}

func identityAssignmentActive(assignment identitymodel.IdentityUserRoleAssignment, now time.Time) bool {
	status := strings.TrimSpace(assignment.Status)
	if status != "" && status != "active" {
		return false
	}
	if validFrom := strings.TrimSpace(assignment.ValidFrom); validFrom != "" {
		parsed, err := time.Parse(time.RFC3339, validFrom)
		if err != nil || now.Before(parsed) {
			return false
		}
	}
	validUntil := strings.TrimSpace(assignment.ValidUntil)
	if validUntil == "" && assignment.ExpiresAt != nil {
		validUntil = strings.TrimSpace(*assignment.ExpiresAt)
	}
	if validUntil != "" {
		parsed, err := time.Parse(time.RFC3339, validUntil)
		if err != nil || !now.Before(parsed) {
			return false
		}
	}
	return true
}

func (s *IdentityDomainService) identityPrivilegedAutoAssignableRole(role identitymodel.IdentityRole) bool {
	definition, published := s.publishedRoleDefinition(role)
	return published && definition.RiskLevel == identitymodel.IdentityRoleRiskPrivileged
}

func (s *IdentityDomainService) RoleByID(ctx context.Context, roleID string) (identitymodel.IdentityRole, bool, error) {
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	for _, role := range roles {
		if role.ID == roleID {
			return role, true, nil
		}
	}
	return identitymodel.IdentityRole{}, false, nil
}

func (s *IdentityDomainService) roleByID(ctx context.Context, roleID string) (identitymodel.IdentityRole, bool, error) {
	return s.RoleByID(ctx, roleID)
}
