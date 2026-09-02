package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityAccessReviewAudit func(context.Context, string, string, identitymodel.Principal, map[string]any)
type IdentityAccessReviewLastUsed func(context.Context, identitymodel.Principal, string, string) (string, bool, error)

type IdentityAccessReviewWorkspaceScope interface {
	ForWorkspace(string) (*IdentityApplicationService, error)
}

type IdentityAccessReviewDependencies struct {
	Identity IdentityAccessReviewWorkspaceScope
	Audit    IdentityAccessReviewAudit
	LastUsed IdentityAccessReviewLastUsed
	Now      func() time.Time
}

type IdentityAccessReviewApplicationService struct {
	dependencies IdentityAccessReviewDependencies
}

func NewIdentityAccessReviewApplicationService(dependencies IdentityAccessReviewDependencies) *IdentityAccessReviewApplicationService {
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &IdentityAccessReviewApplicationService{dependencies: dependencies}
}

func (s *IdentityAccessReviewApplicationService) CreateReview(ctx context.Context, request identitymodel.IdentityAccessReviewCreateRequest, actor identitymodel.Principal) (identitymodel.IdentityAccessReview, error) {
	scoped, repository, workspaceContext, err := s.scope(ctx, actor, "identity.access_reviews.create")
	if err != nil {
		return identitymodel.IdentityAccessReview{}, err
	}
	request.ID = strings.TrimSpace(request.ID)
	periodStart, startErr := time.Parse(time.RFC3339, strings.TrimSpace(request.PeriodStart))
	periodEnd, endErr := time.Parse(time.RFC3339, strings.TrimSpace(request.PeriodEnd))
	dueAt, dueErr := time.Parse(time.RFC3339, strings.TrimSpace(request.DueAt))
	if request.ID == "" || startErr != nil || endErr != nil || dueErr != nil || !periodStart.Before(periodEnd) || dueAt.Before(periodEnd) {
		return identitymodel.IdentityAccessReview{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_period_invalid", nil, nil)
	}
	roles, err := scoped.ListRoles(workspaceContext)
	if err != nil {
		return identitymodel.IdentityAccessReview{}, err
	}
	assignments, err := scoped.ListUserRoleAssignments(workspaceContext, "")
	if err != nil {
		return identitymodel.IdentityAccessReview{}, err
	}
	now := s.dependencies.Now().UTC()
	roleByID := make(map[string]identitymodel.IdentityRole, len(roles))
	definitionByID := make(map[string]identitymodel.RoleSchema, len(roles))
	for _, role := range roles {
		roleByID[role.ID] = role
		if definition, found := scoped.PublishedRoleDefinition(workspaceContext, role.Key); found {
			definitionByID[role.ID] = definition
		}
	}
	items := make([]identitymodel.IdentityAccessReviewItem, 0, len(assignments))
	for _, assignment := range assignments {
		if !identityAccessReviewAssignmentActive(assignment, now) {
			continue
		}
		role, found := roleByID[assignment.RoleID]
		if !found || role.Status != identitymodel.IdentityStatusActive {
			continue
		}
		definition := definitionByID[assignment.RoleID]
		risk := definition.RiskLevel
		if risk == "" {
			risk = identitymodel.IdentityRoleRiskNormal
		}
		lastUsedAt := ""
		lastUsedFound := false
		if s.dependencies.LastUsed != nil {
			lastUsedAt, lastUsedFound, err = s.dependencies.LastUsed(workspaceContext, actor, assignment.UserID, role.Key)
			if err != nil {
				return identitymodel.IdentityAccessReview{}, err
			}
		}
		priority, priorityReasons := identityAccessReviewPriority(assignment, risk, lastUsedAt, lastUsedFound, now)
		item := identitymodel.IdentityAccessReviewItem{
			ID:       identityAccessReviewStableID("access-review-item", request.ID, assignment.UserID, assignment.RoleID),
			ReviewID: request.ID, UserID: assignment.UserID, RoleID: assignment.RoleID, RoleKey: role.Key,
			BindingKey: assignment.BindingKey, ProfileID: assignment.ProfileID,
			RiskLevel: risk, Priority: priority, PriorityReasons: priorityReasons, LastUsedAt: lastUsedAt,
			PermissionStates: identityAccessReviewPermissionStates(definition, scoped.PermissionDefinitions()),
			Status:           "pending", Version: 1, CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return identitymodel.IdentityAccessReview{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_empty", nil, nil)
	}
	sort.Slice(items, func(left, right int) bool {
		leftRank, rightRank := identityAccessReviewPriorityRank(items[left].Priority), identityAccessReviewPriorityRank(items[right].Priority)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return items[left].ID < items[right].ID
	})
	review := identitymodel.IdentityAccessReview{
		ID: request.ID, WorkspaceID: actor.WorkspaceID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339), PeriodEnd: periodEnd.UTC().Format(time.RFC3339), DueAt: dueAt.UTC().Format(time.RFC3339),
		Status: identitymodel.IdentityAccessReviewOpen, CreatedBy: actor.UserID, CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339), Items: items,
	}
	if err := repository.CreateIdentityAccessReview(workspaceContext, review); err != nil {
		return identitymodel.IdentityAccessReview{}, err
	}
	s.audit(workspaceContext, "identity_access_review_created", review.ID, actor, map[string]any{"item_count": len(items), "period_start": review.PeriodStart, "period_end": review.PeriodEnd, "due_at": review.DueAt})
	return review, nil
}

func (s *IdentityAccessReviewApplicationService) ListReviews(ctx context.Context, status string, actor identitymodel.Principal) ([]identitymodel.IdentityAccessReview, error) {
	scoped, repository, workspaceContext, err := s.scope(ctx, actor, "identity.access_reviews.list")
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	if status != "" && status != string(identitymodel.IdentityAccessReviewOpen) && status != string(identitymodel.IdentityAccessReviewCompleted) {
		return nil, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_status_invalid", nil, nil)
	}
	reviews, err := repository.ListIdentityAccessReviews(workspaceContext, actor.WorkspaceID, status)
	if err != nil {
		return nil, err
	}
	permissions := scoped.PermissionDefinitions()
	for reviewIndex := range reviews {
		for itemIndex := range reviews[reviewIndex].Items {
			item := &reviews[reviewIndex].Items[itemIndex]
			definition, _ := scoped.PublishedRoleDefinition(workspaceContext, item.RoleKey)
			item.PermissionStates = identityAccessReviewPermissionStates(definition, permissions)
		}
	}
	return reviews, nil
}

func (s *IdentityAccessReviewApplicationService) Decide(ctx context.Context, itemID string, request identitymodel.IdentityAccessReviewDecisionRequest, actor identitymodel.Principal) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	scoped, repository, workspaceContext, err := s.scope(ctx, actor, "identity.access_review_items.decide")
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	itemID = strings.TrimSpace(itemID)
	request.Reason = strings.TrimSpace(request.Reason)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.ReplacementRoleID = strings.TrimSpace(request.ReplacementRoleID)
	request.ExpiresAt = strings.TrimSpace(request.ExpiresAt)
	if itemID == "" || request.Reason == "" || request.IdempotencyKey == "" || request.ExpectedVersion < 1 {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_decision_invalid", nil, nil)
	}
	fingerprint := identityAccessReviewDecisionFingerprint(actor.UserID, itemID, request)
	if receipt, found, receiptErr := repository.GetIdentityAccessReviewDecisionReceipt(workspaceContext, actor.WorkspaceID, itemID, request.IdempotencyKey); receiptErr != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, receiptErr
	} else if found {
		if receipt.RequestFingerprint != fingerprint {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindConflict, "backend.idempotency_key_reused", nil, nil)
		}
		receipt.Replayed = true
		definition, _ := scoped.PublishedRoleDefinition(workspaceContext, receipt.Item.RoleKey)
		receipt.Item.PermissionStates = identityAccessReviewPermissionStates(definition, scoped.PermissionDefinitions())
		return receipt, nil
	}
	item, found, err := repository.GetIdentityAccessReviewItem(workspaceContext, actor.WorkspaceID, itemID)
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindNotFound, "backend.identity.access_review_item_not_found", nil, nil)
	}
	switch request.Decision {
	case identitymodel.IdentityAccessReviewKeep:
		if request.ReplacementRoleID != "" || request.ExpiresAt != "" {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_decision_invalid", nil, nil)
		}
	case identitymodel.IdentityAccessReviewRevoke:
		if request.ReplacementRoleID != "" || request.ExpiresAt != "" {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_decision_invalid", nil, nil)
		}
		_, _, err = scoped.PrepareIdentityEntitlementBatch(workspaceContext, []identitymodel.IdentityEntitlementBatchItem{{
			Operation: identitymodel.IdentityEntitlementOperationRevoke, UserID: item.UserID, RoleID: item.RoleID, Reason: request.Reason,
		}}, actor)
	case identitymodel.IdentityAccessReviewReduceScope:
		if request.ReplacementRoleID == "" || request.ReplacementRoleID == item.RoleID || request.ExpiresAt != "" {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_replacement_role_required", nil, nil)
		}
		err = s.validateReducedRole(workspaceContext, scoped, item, request, actor)
	case identitymodel.IdentityAccessReviewSetExpiry:
		var expiresAt time.Time
		expiresAt, err = time.Parse(time.RFC3339, request.ExpiresAt)
		if err == nil && !expiresAt.After(s.dependencies.Now().UTC()) {
			err = apperror.New(apperror.KindBadRequest, "backend.identity.access_review_expiry_invalid", nil, nil)
		}
		if request.ReplacementRoleID != "" {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_decision_invalid", nil, nil)
		}
	default:
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_decision_invalid", nil, nil)
	}
	if err != nil {
		var appErr *apperror.AppError
		if errors.As(err, &appErr) {
			return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
		}
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.access_review_expiry_invalid", err, nil)
	}
	receipt, err := repository.ApplyIdentityAccessReviewDecision(workspaceContext, identitymodel.IdentityAccessReviewDecisionMutation{
		WorkspaceID: actor.WorkspaceID, ItemID: itemID, ReviewerID: actor.UserID, Request: request, RequestFingerprint: fingerprint,
	})
	if err != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, err
	}
	if !receipt.Replayed {
		s.audit(workspaceContext, "identity_access_review_decided", itemID, actor, map[string]any{
			"decision": request.Decision, "review_id": item.ReviewID, "user_id": item.UserID, "role_id": item.RoleID,
			"replacement_role_id": request.ReplacementRoleID, "expires_at": request.ExpiresAt, "reason": request.Reason,
		})
	}
	definition, _ := scoped.PublishedRoleDefinition(workspaceContext, receipt.Item.RoleKey)
	receipt.Item.PermissionStates = identityAccessReviewPermissionStates(definition, scoped.PermissionDefinitions())
	return receipt, nil
}

func identityAccessReviewPermissionStates(role identitymodel.RoleSchema, definitions map[string]identitymodel.IdentityPermissionDefinition) []identitymodel.IdentityAccessReviewPermissionState {
	keys := append([]string(nil), role.Permissions...)
	sort.Strings(keys)
	states := make([]identitymodel.IdentityAccessReviewPermissionState, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || len(states) != 0 && states[len(states)-1].PermissionKey == key {
			continue
		}
		definition, found := definitions[key]
		state := identitymodel.IdentityAccessReviewPermissionState{PermissionKey: key, State: "unknown"}
		if found {
			state.DefinitionStatus = definition.DefinitionStatus
			state.Enabled = definition.Enabled
			state.SourceOwner = definition.SourceOwner
			switch {
			case definition.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive:
				state.State = "retired"
			case !definition.Enabled:
				state.State = "disabled"
			default:
				state.State = "active"
			}
		}
		states = append(states, state)
	}
	return states
}

func (s *IdentityAccessReviewApplicationService) validateReducedRole(ctx context.Context, scoped *IdentityApplicationService, item identitymodel.IdentityAccessReviewItem, request identitymodel.IdentityAccessReviewDecisionRequest, actor identitymodel.Principal) error {
	roles, err := scoped.ListRoles(ctx)
	if err != nil {
		return err
	}
	currentDefinition, replacementDefinition := identitymodel.RoleSchema{}, identitymodel.RoleSchema{}
	for _, role := range roles {
		definition, found := scoped.PublishedRoleDefinition(ctx, role.Key)
		if !found {
			continue
		}
		if role.ID == item.RoleID {
			currentDefinition = definition
		}
		if role.ID == request.ReplacementRoleID {
			replacementDefinition = definition
		}
	}
	if replacementDefinition.Key == "" {
		return apperror.New(apperror.KindBadRequest, "backend.identity.role_not_found", nil, nil)
	}
	if !identityAccessReviewRoleIsReduction(currentDefinition, replacementDefinition) {
		return apperror.New(apperror.KindForbidden, "backend.identity.access_review_not_a_reduction", nil, nil)
	}
	_, _, err = scoped.PrepareIdentityEntitlementBatch(ctx, []identitymodel.IdentityEntitlementBatchItem{
		{Operation: identitymodel.IdentityEntitlementOperationRevoke, UserID: item.UserID, RoleID: item.RoleID, Reason: request.Reason},
		{Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: item.UserID, RoleID: request.ReplacementRoleID, BindingKey: item.BindingKey, ProfileID: item.ProfileID, Reason: request.Reason},
	}, actor)
	return err
}

func (s *IdentityAccessReviewApplicationService) scope(ctx context.Context, actor identitymodel.Principal, actionKey string) (*IdentityApplicationService, identityrepository.IdentityAccessReviewRepository, context.Context, error) {
	if err := identityAuthorizeQuery(actor); err != nil {
		return nil, nil, nil, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(actor.Role, actionKey) {
		return nil, nil, nil, apperror.New(apperror.KindForbidden, "backend.permission.denied", nil, nil)
	}
	if s == nil || s.dependencies.Identity == nil {
		return nil, nil, nil, internalError("access review", nil)
	}
	scoped, err := s.dependencies.Identity.ForWorkspace(actor.WorkspaceID)
	if err != nil {
		return nil, nil, nil, err
	}
	repository, ok := scoped.Repository().(identityrepository.IdentityAccessReviewRepository)
	if !ok {
		return nil, nil, nil, apperror.New(apperror.KindInternal, "backend.identity.access_review_unavailable", nil, nil)
	}
	return scoped, repository, requestcontext.WithWorkspaceID(ctx, actor.WorkspaceID), nil
}

func (s *IdentityAccessReviewApplicationService) audit(ctx context.Context, event, recordID string, actor identitymodel.Principal, metadata map[string]any) {
	if s != nil && s.dependencies.Audit != nil {
		s.dependencies.Audit(ctx, event, recordID, actor, metadata)
	}
}

func identityAccessReviewPriority(assignment identitymodel.IdentityUserRoleAssignment, risk identitymodel.IdentityRoleRiskLevel, lastUsedAt string, lastUsedFound bool, now time.Time) (string, []string) {
	reasons := []string{}
	if risk == identitymodel.IdentityRoleRiskPrivileged {
		reasons = append(reasons, "privileged")
	}
	if risk == identitymodel.IdentityRoleRiskElevated {
		reasons = append(reasons, "elevated")
	}
	staleBefore := now.Add(-90 * 24 * time.Hour)
	if lastUsedFound {
		if parsed, err := time.Parse(time.RFC3339, lastUsedAt); err == nil && parsed.Before(staleBefore) {
			reasons = append(reasons, "long_unused")
		}
	} else if createdAt, err := time.Parse(time.RFC3339, assignment.CreatedAt); err == nil && createdAt.Before(staleBefore) {
		reasons = append(reasons, "never_used")
	}
	sort.Strings(reasons)
	if risk == identitymodel.IdentityRoleRiskPrivileged {
		return "critical", reasons
	}
	if len(reasons) > 0 {
		return "high", reasons
	}
	return "normal", reasons
}

func identityAccessReviewPriorityRank(priority string) int {
	switch priority {
	case "critical":
		return 0
	case "high":
		return 1
	default:
		return 2
	}
}

func identityAccessReviewAssignmentActive(assignment identitymodel.IdentityUserRoleAssignment, now time.Time) bool {
	if assignment.Status == "revoked" {
		return false
	}
	if assignment.ValidFrom != "" {
		if from, err := time.Parse(time.RFC3339, assignment.ValidFrom); err == nil && now.Before(from) {
			return false
		}
	}
	until := assignment.ValidUntil
	if assignment.ExpiresAt != nil && strings.TrimSpace(*assignment.ExpiresAt) != "" {
		until = *assignment.ExpiresAt
	}
	if until != "" {
		if parsed, err := time.Parse(time.RFC3339, until); err == nil && !now.Before(parsed) {
			return false
		}
	}
	return true
}

func identityAccessReviewRoleIsReduction(current, replacement identitymodel.RoleSchema) bool {
	if current.Key == "" || replacement.Key == "" {
		return false
	}
	currentPermissions := map[string]bool{}
	for _, permission := range current.Permissions {
		currentPermissions[strings.TrimSpace(permission)] = true
	}
	for _, permission := range replacement.Permissions {
		if !currentPermissions[strings.TrimSpace(permission)] {
			return false
		}
	}
	rank := map[identitymodel.IdentityRoleRiskLevel]int{identitymodel.IdentityRoleRiskNormal: 0, identitymodel.IdentityRoleRiskElevated: 1, identitymodel.IdentityRoleRiskPrivileged: 2}
	return rank[replacement.RiskLevel] <= rank[current.RiskLevel] && (len(replacement.Permissions) < len(current.Permissions) || rank[replacement.RiskLevel] < rank[current.RiskLevel])
}

func identityAccessReviewStableID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func identityAccessReviewDecisionFingerprint(actorID, itemID string, request identitymodel.IdentityAccessReviewDecisionRequest) string {
	raw, _ := json.Marshal(struct {
		ActorID string                                            `json:"actor_id"`
		ItemID  string                                            `json:"item_id"`
		Request identitymodel.IdentityAccessReviewDecisionRequest `json:"request"`
	}{ActorID: strings.TrimSpace(actorID), ItemID: strings.TrimSpace(itemID), Request: request})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
