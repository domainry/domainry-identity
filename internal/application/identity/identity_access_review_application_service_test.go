package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type accessReviewFaultRepository struct {
	*identityScopedRepository
	listRolesErr, listAssignmentsErr, createErr, listReviewsErr error
	getItemErr, getReceiptErr, applyErr                         error
	applyReceipt                                                *identitymodel.IdentityAccessReviewDecisionReceipt
	workforceProfiles                                           []identitymodel.IdentityWorkforceProfile
	workforceAssignments                                        map[string][]identitymodel.IdentityWorkforceAssignment
	listWorkforceProfilesErr, listWorkforceAssignmentsErr       error
}

type accessReviewUnavailableRepository struct {
	identityrepository.IdentityRepository
}

type accessReviewFailingWorkspaceScope struct {
	err error
}

func (s accessReviewFailingWorkspaceScope) ForWorkspace(string) (*IdentityApplicationService, error) {
	return nil, s.err
}

func (r *accessReviewFaultRepository) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	if r.listRolesErr != nil {
		return nil, r.listRolesErr
	}
	return r.identityScopedRepository.ListIdentityRoles(ctx, workspaceID)
}

func (r *accessReviewFaultRepository) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.listAssignmentsErr != nil {
		return nil, r.listAssignmentsErr
	}
	return r.identityScopedRepository.ListIdentityUserRoleAssignments(ctx, workspaceID, userID)
}

func (r *accessReviewFaultRepository) CreateIdentityAccessReview(ctx context.Context, review identitymodel.IdentityAccessReview) error {
	if r.createErr != nil {
		return r.createErr
	}
	return r.identityScopedRepository.CreateIdentityAccessReview(ctx, review)
}

func (r *accessReviewFaultRepository) ListIdentityAccessReviews(ctx context.Context, workspaceID, status string) ([]identitymodel.IdentityAccessReview, error) {
	if r.listReviewsErr != nil {
		return nil, r.listReviewsErr
	}
	return r.identityScopedRepository.ListIdentityAccessReviews(ctx, workspaceID, status)
}

func (r *accessReviewFaultRepository) GetIdentityAccessReviewItem(ctx context.Context, workspaceID, itemID string) (identitymodel.IdentityAccessReviewItem, bool, error) {
	if r.getItemErr != nil {
		return identitymodel.IdentityAccessReviewItem{}, false, r.getItemErr
	}
	return r.identityScopedRepository.GetIdentityAccessReviewItem(ctx, workspaceID, itemID)
}

func (r *accessReviewFaultRepository) GetIdentityAccessReviewDecisionReceipt(ctx context.Context, workspaceID, itemID, idempotencyKey string) (identitymodel.IdentityAccessReviewDecisionReceipt, bool, error) {
	if r.getReceiptErr != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, false, r.getReceiptErr
	}
	return r.identityScopedRepository.GetIdentityAccessReviewDecisionReceipt(ctx, workspaceID, itemID, idempotencyKey)
}

func (r *accessReviewFaultRepository) ApplyIdentityAccessReviewDecision(ctx context.Context, mutation identitymodel.IdentityAccessReviewDecisionMutation) (identitymodel.IdentityAccessReviewDecisionReceipt, error) {
	if r.applyErr != nil {
		return identitymodel.IdentityAccessReviewDecisionReceipt{}, r.applyErr
	}
	if r.applyReceipt != nil {
		return *r.applyReceipt, nil
	}
	return r.identityScopedRepository.ApplyIdentityAccessReviewDecision(ctx, mutation)
}

func (r *accessReviewFaultRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	if r.listWorkforceProfilesErr != nil {
		return nil, r.listWorkforceProfilesErr
	}
	return r.workforceProfiles, nil
}

func (r *accessReviewFaultRepository) GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return identitymodel.IdentityWorkforceProfile{}, false, nil
}

func (r *accessReviewFaultRepository) UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error {
	return nil
}

func (r *accessReviewFaultRepository) ListIdentityWorkforceAssignments(_ context.Context, _, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	if r.listWorkforceAssignmentsErr != nil {
		return nil, r.listWorkforceAssignmentsErr
	}
	return r.workforceAssignments[profileID], nil
}

func (r *accessReviewFaultRepository) GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return identitymodel.IdentityWorkforceAssignment{}, false, nil
}

func (r *accessReviewFaultRepository) UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error {
	return nil
}

func TestAccessReviewCreatesPrioritizedPeriodicQueueAndAuditsDecisionsOnce(t *testing.T) {
	repository := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "role-admin", Key: "admin", Status: identitymodel.IdentityStatusActive},
			{ID: "role-reader", Key: "reader", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user-1", RoleID: "role-reader", Status: "active", CreatedAt: "2025-01-01T00:00:00Z"},
			{UserID: "admin-1", RoleID: "role-admin", Status: "active", CreatedAt: "2026-06-01T00:00:00Z"},
		},
	}
	identity := NewIdentityApplicationService(repository, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", Permissions: []string{"identity.roles.list"}, RiskLevel: identitymodel.IdentityRoleRiskPrivileged, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "reader", Permissions: []string{"crm.member.read"}, RiskLevel: identitymodel.IdentityRoleRiskNormal, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	audits := []string{}
	service := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{
		Identity: identity, Now: func() time.Time { return now },
		Audit: func(_ context.Context, event, _ string, _ identitymodel.Principal, _ map[string]any) {
			audits = append(audits, event)
		},
		LastUsed: func(_ context.Context, _ identitymodel.Principal, _ string, roleKey string) (string, bool, error) {
			if roleKey == "reader" {
				return "2025-12-01T00:00:00Z", true, nil
			}
			return "2026-07-24T00:00:00Z", true, nil
		},
	})
	actor := identitymodel.Principal{
		Known: true, UserID: "admin-1", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: identityAccessReviewTestPermissions(), GrantableRoleKeys: []string{"*"}},
	}
	review, err := service.CreateReview(t.Context(), identitymodel.IdentityAccessReviewCreateRequest{
		ID: "quarter-2", PeriodStart: "2026-04-01T00:00:00Z", PeriodEnd: "2026-06-30T00:00:00Z", DueAt: "2026-07-31T00:00:00Z",
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Items) != 2 || review.Items[0].RoleKey != "admin" || review.Items[0].Priority != "critical" || review.Items[1].Priority != "high" {
		t.Fatalf("review priority queue=%#v", review.Items)
	}
	if review.Items[1].LastUsedAt != "2025-12-01T00:00:00Z" || len(review.Items[1].PriorityReasons) != 1 || review.Items[1].PriorityReasons[0] != "long_unused" {
		t.Fatalf("long-unused evidence=%#v", review.Items[1])
	}
	if len(review.Items[1].PermissionStates) != 1 || review.Items[1].PermissionStates[0].State != "unknown" {
		t.Fatalf("initial permission state=%#v", review.Items[1].PermissionStates)
	}
	if len(audits) != 1 || audits[0] != "identity_access_review_created" {
		t.Fatalf("create audits=%#v", audits)
	}
	identity.ReplacePermissionDefinitions([]identitymodel.IdentityPermissionDefinition{{
		Key: "crm.member.read", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive,
		Enabled: false, SourceOwner: "application:crm",
	}})
	reviews, err := service.ListReviews(t.Context(), "open", actor)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews=%#v err=%v", reviews, err)
	}
	if state := reviews[0].Items[1].PermissionStates; len(state) != 1 || state[0].State != "disabled" || state[0].SourceOwner != "application:crm" {
		t.Fatalf("current permission state=%#v", state)
	}
	readerItem := review.Items[1]
	request := identitymodel.IdentityAccessReviewDecisionRequest{
		Decision: identitymodel.IdentityAccessReviewKeep, Reason: "still required", ExpectedVersion: 1, IdempotencyKey: "keep-reader",
	}
	receipt, err := service.Decide(t.Context(), readerItem.ID, request, actor)
	if err != nil || receipt.Replayed || receipt.Item.Decision != identitymodel.IdentityAccessReviewKeep {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	replay, err := service.Decide(t.Context(), readerItem.ID, request, actor)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	if len(audits) != 2 || audits[1] != "identity_access_review_decided" {
		t.Fatalf("decision replay wrote duplicate audit: %#v", audits)
	}
}

func TestAccessReviewDecisionTreatsWorkspaceCapabilityAsOrdinaryExactGrantAndValidatesShape(t *testing.T) {
	repository := &identityScopedRepository{
		roles:       []identitymodel.IdentityRole{{ID: "role-admin", Key: "admin", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "admin-1", RoleID: "role-admin", Status: "active"}},
		reviews: []identitymodel.IdentityAccessReview{{
			ID: "review", Status: identitymodel.IdentityAccessReviewOpen,
			Items: []identitymodel.IdentityAccessReviewItem{{ID: "item", ReviewID: "review", UserID: "admin-1", RoleID: "role-admin", RoleKey: "admin", Status: "pending", Version: 1}},
		}},
	}
	identity := NewIdentityApplicationService(repository, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "admin", Permissions: []string{"identity.roles.list"}, RiskLevel: identitymodel.IdentityRoleRiskPrivileged, AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
	}})
	service := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{Identity: identity, Now: func() time.Time {
		return time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	}})
	actor := identitymodel.Principal{Known: true, UserID: "reviewer", WorkspaceID: "workspace", Role: identitymodel.RoleSchema{Permissions: identityAccessReviewTestPermissions(), GrantableRoleKeys: []string{"*"}}}
	if _, err := service.Decide(t.Context(), "item", identitymodel.IdentityAccessReviewDecisionRequest{
		Decision: identitymodel.IdentityAccessReviewSetExpiry, ExpiresAt: "2026-07-25T11:00:00Z", Reason: "temporary", ExpectedVersion: 1, IdempotencyKey: "expiry",
	}, actor); apperror.CodeOf(err) != "backend.identity.access_review_expiry_invalid" {
		t.Fatalf("past expiry error=%v", err)
	}
	if receipt, err := service.Decide(t.Context(), "item", identitymodel.IdentityAccessReviewDecisionRequest{
		Decision: identitymodel.IdentityAccessReviewRevoke, Reason: "remove", ExpectedVersion: 1, IdempotencyKey: "revoke",
	}, actor); err != nil || receipt.Item.Decision != identitymodel.IdentityAccessReviewRevoke {
		t.Fatalf("ordinary exact workspace capability revocation receipt=%+v err=%v", receipt, err)
	}
	outsider := actor
	outsider.Role = identitymodel.RoleSchema{}
	if _, err := service.ListReviews(t.Context(), "", outsider); apperror.CodeOf(err) != "backend.permission.denied" {
		t.Fatalf("non-admin list error=%v", err)
	}
}

func TestAccessReviewRoleReductionMustBeARealPermissionAndRiskReduction(t *testing.T) {
	current := identitymodel.RoleSchema{Key: "current", Permissions: []string{"read", "write"}, RiskLevel: identitymodel.IdentityRoleRiskElevated}
	reduced := identitymodel.RoleSchema{Key: "reduced", Permissions: []string{"read"}, RiskLevel: identitymodel.IdentityRoleRiskNormal}
	if !identityAccessReviewRoleIsReduction(current, reduced) {
		t.Fatal("strict permission and risk reduction was rejected")
	}
	if identityAccessReviewRoleIsReduction(current, identitymodel.RoleSchema{Key: "expanded", Permissions: []string{"read", "delete"}, RiskLevel: identitymodel.IdentityRoleRiskNormal}) {
		t.Fatal("expanded permissions were treated as a reduction")
	}
	if identityAccessReviewRoleIsReduction(current, current) {
		t.Fatal("unchanged role was treated as a reduction")
	}
}

func TestAccessReviewPriorityIncludesCrossOrganizationAndNeverUsedEvidence(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	priority, reasons := identityAccessReviewPriority(identitymodel.IdentityUserRoleAssignment{
		WorkforceProfileID: "workforce-1", CreatedAt: "2025-01-01T00:00:00Z",
	}, identitymodel.IdentityRoleRiskElevated, map[string]int{"workforce-1": 2}, "", false, now)
	if priority != "high" || len(reasons) != 3 || reasons[0] != "cross_organization" || reasons[1] != "elevated" || reasons[2] != "never_used" {
		t.Fatalf("priority=%q reasons=%#v", priority, reasons)
	}
}

func TestAccessReviewPriorityAssignmentAndReductionEdgeOutcomes(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-100 * 24 * time.Hour).Format(time.RFC3339)
	fresh := now.Add(-24 * time.Hour).Format(time.RFC3339)

	priorityTests := []struct {
		name          string
		assignment    identitymodel.IdentityUserRoleAssignment
		risk          identitymodel.IdentityRoleRiskLevel
		lastUsedAt    string
		lastUsedFound bool
		wantPriority  string
		wantReason    string
	}{
		{name: "privileged", risk: identitymodel.IdentityRoleRiskPrivileged, lastUsedAt: fresh, lastUsedFound: true, wantPriority: "critical", wantReason: "privileged"},
		{name: "normal fresh used", lastUsedAt: fresh, lastUsedFound: true, wantPriority: "normal"},
		{name: "normal stale used", lastUsedAt: stale, lastUsedFound: true, wantPriority: "high", wantReason: "long_unused"},
		{name: "invalid last used", lastUsedAt: "invalid", lastUsedFound: true, wantPriority: "normal"},
		{name: "fresh never used", assignment: identitymodel.IdentityUserRoleAssignment{CreatedAt: fresh}, wantPriority: "normal"},
		{name: "invalid created", assignment: identitymodel.IdentityUserRoleAssignment{CreatedAt: "invalid"}, wantPriority: "normal"},
	}
	for _, test := range priorityTests {
		t.Run(test.name, func(t *testing.T) {
			priority, reasons := identityAccessReviewPriority(test.assignment, test.risk, nil, test.lastUsedAt, test.lastUsedFound, now)
			if priority != test.wantPriority {
				t.Fatalf("priority=%q reasons=%v", priority, reasons)
			}
			if test.wantReason != "" && (len(reasons) == 0 || reasons[0] != test.wantReason) {
				t.Fatalf("reasons=%v want=%q", reasons, test.wantReason)
			}
		})
	}
	if identityAccessReviewPriorityRank("critical") != 0 || identityAccessReviewPriorityRank("high") != 1 || identityAccessReviewPriorityRank("normal") != 2 {
		t.Fatal("priority rank mismatch")
	}

	expiresPast := now.Add(-time.Hour).Format(time.RFC3339)
	expiresFuture := now.Add(time.Hour).Format(time.RFC3339)
	activeTests := []struct {
		name       string
		assignment identitymodel.IdentityUserRoleAssignment
		active     bool
	}{
		{name: "ordinary", active: true},
		{name: "revoked", assignment: identitymodel.IdentityUserRoleAssignment{Status: "revoked"}},
		{name: "future valid from", assignment: identitymodel.IdentityUserRoleAssignment{ValidFrom: expiresFuture}},
		{name: "past valid from", assignment: identitymodel.IdentityUserRoleAssignment{ValidFrom: expiresPast}, active: true},
		{name: "invalid valid from", assignment: identitymodel.IdentityUserRoleAssignment{ValidFrom: "invalid"}, active: true},
		{name: "past valid until", assignment: identitymodel.IdentityUserRoleAssignment{ValidUntil: expiresPast}},
		{name: "future valid until", assignment: identitymodel.IdentityUserRoleAssignment{ValidUntil: expiresFuture}, active: true},
		{name: "invalid valid until", assignment: identitymodel.IdentityUserRoleAssignment{ValidUntil: "invalid"}, active: true},
		{name: "past expires at", assignment: identitymodel.IdentityUserRoleAssignment{ExpiresAt: &expiresPast}},
		{name: "future expires at", assignment: identitymodel.IdentityUserRoleAssignment{ExpiresAt: &expiresFuture}, active: true},
		{name: "blank expires at falls back", assignment: identitymodel.IdentityUserRoleAssignment{ExpiresAt: new(string), ValidUntil: expiresFuture}, active: true},
	}
	for _, test := range activeTests {
		t.Run(test.name, func(t *testing.T) {
			if active := identityAccessReviewAssignmentActive(test.assignment, now); active != test.active {
				t.Fatalf("active=%v want=%v assignment=%#v", active, test.active, test.assignment)
			}
		})
	}

	current := identitymodel.RoleSchema{Key: "current", Permissions: []string{"read", "write"}, RiskLevel: identitymodel.IdentityRoleRiskElevated}
	reductionTests := []struct {
		name        string
		current     identitymodel.RoleSchema
		replacement identitymodel.RoleSchema
		reduction   bool
	}{
		{name: "missing current", replacement: identitymodel.RoleSchema{Key: "replacement"}},
		{name: "missing replacement", current: current},
		{name: "permission removed", current: current, replacement: identitymodel.RoleSchema{Key: "replacement", Permissions: []string{" read "}, RiskLevel: identitymodel.IdentityRoleRiskElevated}, reduction: true},
		{name: "risk reduced", current: current, replacement: identitymodel.RoleSchema{Key: "replacement", Permissions: []string{"read", "write"}, RiskLevel: identitymodel.IdentityRoleRiskNormal}, reduction: true},
		{name: "risk expanded", current: current, replacement: identitymodel.RoleSchema{Key: "replacement", Permissions: []string{"read"}, RiskLevel: identitymodel.IdentityRoleRiskPrivileged}},
		{name: "permission expanded", current: current, replacement: identitymodel.RoleSchema{Key: "replacement", Permissions: []string{"read", "delete"}, RiskLevel: identitymodel.IdentityRoleRiskNormal}},
	}
	for _, test := range reductionTests {
		t.Run(test.name, func(t *testing.T) {
			if reduction := identityAccessReviewRoleIsReduction(test.current, test.replacement); reduction != test.reduction {
				t.Fatalf("reduction=%v want=%v", reduction, test.reduction)
			}
		})
	}

	if identityAccessReviewStableID("a", "b") != identityAccessReviewStableID("a", "b") ||
		identityAccessReviewStableID("a", "b") == identityAccessReviewStableID("ab") {
		t.Fatal("stable identity hashing mismatch")
	}
	request := identitymodel.IdentityAccessReviewDecisionRequest{Decision: identitymodel.IdentityAccessReviewKeep, Reason: "reason"}
	if identityAccessReviewDecisionFingerprint(" actor ", " item ", request) != identityAccessReviewDecisionFingerprint("actor", "item", request) {
		t.Fatal("decision fingerprint did not normalize identity")
	}
}

func TestAccessReviewCreateValidationAndDependencyFailures(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	valid := identitymodel.IdentityAccessReviewCreateRequest{
		ID: "review", PeriodStart: "2026-04-01T00:00:00Z", PeriodEnd: "2026-06-30T00:00:00Z", DueAt: "2026-07-31T00:00:00Z",
	}
	actor := identitymodel.Principal{
		Known: true, UserID: "reviewer", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: identityAccessReviewTestPermissions(), GrantableRoleKeys: []string{"*"}},
	}
	base := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "role", Key: "reader", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{
			UserID: "user", RoleID: "role", Status: "active", CreatedAt: now.Format(time.RFC3339),
		}},
	}
	newService := func(repository identityrepository.IdentityRepository, lastUsed IdentityAccessReviewLastUsed) *IdentityAccessReviewApplicationService {
		identity := NewIdentityApplicationService(repository, nil)
		identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "reader", Permissions: []string{"read"}}})
		return NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{
			Identity: identity, LastUsed: lastUsed, Now: func() time.Time { return now },
		})
	}
	invalid := []struct {
		name   string
		mutate func(*identitymodel.IdentityAccessReviewCreateRequest)
	}{
		{name: "blank id", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.ID = " " }},
		{name: "invalid start", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.PeriodStart = "invalid" }},
		{name: "invalid end", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.PeriodEnd = "invalid" }},
		{name: "invalid due", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.DueAt = "invalid" }},
		{name: "reversed period", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.PeriodStart = r.PeriodEnd }},
		{name: "due before end", mutate: func(r *identitymodel.IdentityAccessReviewCreateRequest) { r.DueAt = "2026-06-01T00:00:00Z" }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := newService(base, nil).CreateReview(t.Context(), request, actor); apperror.CodeOf(err) != "backend.identity.access_review_period_invalid" {
				t.Fatalf("error=%v", err)
			}
		})
	}

	fault := &accessReviewFaultRepository{identityScopedRepository: base}
	failures := []struct {
		name string
		set  func(error)
	}{
		{name: "roles", set: func(err error) { fault.listRolesErr = err }},
		{name: "assignments", set: func(err error) { fault.listAssignmentsErr = err }},
		{name: "workforce profiles", set: func(err error) { fault.listWorkforceProfilesErr = err }},
		{name: "workforce assignments", set: func(err error) {
			fault.workforceProfiles = []identitymodel.IdentityWorkforceProfile{{ID: "profile"}}
			fault.listWorkforceAssignmentsErr = err
		}},
		{name: "create", set: func(err error) { fault.createErr = err }},
	}
	for _, test := range failures {
		t.Run(test.name, func(t *testing.T) {
			*fault = accessReviewFaultRepository{identityScopedRepository: base}
			expected := errors.New(test.name)
			test.set(expected)
			if _, err := newService(fault, nil).CreateReview(t.Context(), valid, actor); !errors.Is(err, expected) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	lastUsedErr := errors.New("last used")
	if _, err := newService(fault, func(context.Context, identitymodel.Principal, string, string) (string, bool, error) {
		return "", false, lastUsedErr
	}).CreateReview(t.Context(), valid, actor); !errors.Is(err, lastUsedErr) {
		t.Fatalf("last used error=%v", err)
	}

	inactive := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{
			{ID: "inactive-role", Key: "inactive", Status: "inactive"},
			{ID: "active-role", Key: "active", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "one", RoleID: "inactive-role"},
			{UserID: "two", RoleID: "missing"},
			{UserID: "three", RoleID: "active-role", Status: "revoked"},
		},
	}
	if _, err := newService(inactive, nil).CreateReview(t.Context(), valid, actor); apperror.CodeOf(err) != "backend.identity.access_review_empty" {
		t.Fatalf("empty review error=%v", err)
	}
	samePriority := &identityScopedRepository{
		roles: []identitymodel.IdentityRole{{ID: "role", Key: "reader", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{
			{UserID: "user-b", RoleID: "role", Status: "active", CreatedAt: now.Format(time.RFC3339)},
			{UserID: "user-a", RoleID: "role", Status: "active", CreatedAt: now.Format(time.RFC3339)},
		},
	}
	if _, err := newService(samePriority, nil).CreateReview(t.Context(), valid, actor); err != nil {
		t.Fatalf("same-priority review: %v", err)
	}
	unauthorized := actor
	unauthorized.Known = false
	if _, err := newService(base, nil).CreateReview(t.Context(), valid, unauthorized); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unauthorized create=%v", err)
	}
}

func TestAccessReviewListScopeAndDecisionEdgeOutcomes(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	actor := identitymodel.Principal{
		Known: true, UserID: "reviewer", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: identityAccessReviewTestPermissions(), GrantableRoleKeys: []string{"*"}},
	}
	base := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "current", Key: "current", Status: identitymodel.IdentityStatusActive},
			{ID: "reduced", Key: "reduced", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "current", Status: "active"}},
		reviews: []identitymodel.IdentityAccessReview{{ID: "review", Status: identitymodel.IdentityAccessReviewOpen, Items: []identitymodel.IdentityAccessReviewItem{{
			ID: "item", ReviewID: "review", UserID: "user", RoleID: "current", RoleKey: "current", Status: "pending", Version: 1,
		}}}},
	}
	fault := &accessReviewFaultRepository{identityScopedRepository: base}
	identity := NewIdentityApplicationService(fault, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "current", Permissions: []string{"read", "write"}, RiskLevel: identitymodel.IdentityRoleRiskElevated},
		{Key: "reduced", Permissions: []string{"read"}, RiskLevel: identitymodel.IdentityRoleRiskNormal},
	})
	service := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{Identity: identity, Now: func() time.Time { return now }})

	for _, status := range []string{"", "open", "completed"} {
		if _, err := service.ListReviews(t.Context(), status, actor); err != nil {
			t.Fatalf("status %q: %v", status, err)
		}
	}
	if _, err := service.ListReviews(t.Context(), "draft", actor); apperror.CodeOf(err) != "backend.identity.access_review_status_invalid" {
		t.Fatalf("invalid status error=%v", err)
	}
	fault.listReviewsErr = errors.New("list reviews")
	if _, err := service.ListReviews(t.Context(), "", actor); !errors.Is(err, fault.listReviewsErr) {
		t.Fatalf("list error=%v", err)
	}
	fault.listReviewsErr = nil

	valid := identitymodel.IdentityAccessReviewDecisionRequest{
		Decision: identitymodel.IdentityAccessReviewKeep, Reason: "needed", ExpectedVersion: 1, IdempotencyKey: "key",
	}
	invalid := []struct {
		name   string
		itemID string
		mutate func(*identitymodel.IdentityAccessReviewDecisionRequest)
	}{
		{name: "blank item", itemID: " ", mutate: func(*identitymodel.IdentityAccessReviewDecisionRequest) {}},
		{name: "blank reason", itemID: "item", mutate: func(r *identitymodel.IdentityAccessReviewDecisionRequest) { r.Reason = " " }},
		{name: "blank key", itemID: "item", mutate: func(r *identitymodel.IdentityAccessReviewDecisionRequest) { r.IdempotencyKey = " " }},
		{name: "bad version", itemID: "item", mutate: func(r *identitymodel.IdentityAccessReviewDecisionRequest) { r.ExpectedVersion = 0 }},
	}
	for _, test := range invalid {
		request := valid
		test.mutate(&request)
		if _, err := service.Decide(t.Context(), test.itemID, request, actor); apperror.CodeOf(err) != "backend.identity.access_review_decision_invalid" {
			t.Fatalf("%s error=%v", test.name, err)
		}
	}
	fault.getReceiptErr = errors.New("get receipt")
	if _, err := service.Decide(t.Context(), "item", valid, actor); !errors.Is(err, fault.getReceiptErr) {
		t.Fatalf("receipt error=%v", err)
	}
	fault.getReceiptErr = nil
	fingerprint := identityAccessReviewDecisionFingerprint(actor.UserID, "item", valid)
	base.reviewReceipts = map[string]identitymodel.IdentityAccessReviewDecisionReceipt{
		"item\x00key": {RequestFingerprint: fingerprint + "-different"},
	}
	if _, err := service.Decide(t.Context(), "item", valid, actor); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("fingerprint conflict=%v", err)
	}
	base.reviewReceipts = nil
	fault.getItemErr = errors.New("get item")
	if _, err := service.Decide(t.Context(), "item", valid, actor); !errors.Is(err, fault.getItemErr) {
		t.Fatalf("item error=%v", err)
	}
	fault.getItemErr = nil
	if _, err := service.Decide(t.Context(), "missing", valid, actor); apperror.CodeOf(err) != "backend.identity.access_review_item_not_found" {
		t.Fatalf("missing item=%v", err)
	}

	shapeTests := []identitymodel.IdentityAccessReviewDecisionRequest{
		{Decision: identitymodel.IdentityAccessReviewKeep, ReplacementRoleID: "x"},
		{Decision: identitymodel.IdentityAccessReviewKeep, ExpiresAt: "future"},
		{Decision: identitymodel.IdentityAccessReviewRevoke, ReplacementRoleID: "x"},
		{Decision: identitymodel.IdentityAccessReviewRevoke, ExpiresAt: "future"},
		{Decision: identitymodel.IdentityAccessReviewReduceScope},
		{Decision: identitymodel.IdentityAccessReviewReduceScope, ReplacementRoleID: "current"},
		{Decision: identitymodel.IdentityAccessReviewReduceScope, ReplacementRoleID: "reduced", ExpiresAt: "future"},
		{Decision: identitymodel.IdentityAccessReviewSetExpiry, ReplacementRoleID: "reduced", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{Decision: "unknown"},
	}
	for index, request := range shapeTests {
		request.Reason, request.ExpectedVersion, request.IdempotencyKey = "reason", 1, "shape-"+time.Duration(index).String()
		if _, err := service.Decide(t.Context(), "item", request, actor); err == nil {
			t.Fatalf("shape %d unexpectedly succeeded", index)
		}
	}

	successes := []identitymodel.IdentityAccessReviewDecisionRequest{
		{Decision: identitymodel.IdentityAccessReviewRevoke},
		{Decision: identitymodel.IdentityAccessReviewReduceScope, ReplacementRoleID: "reduced"},
		{Decision: identitymodel.IdentityAccessReviewSetExpiry, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
	}
	for index, request := range successes {
		request.Reason, request.ExpectedVersion, request.IdempotencyKey = "reason", 1, "success-"+time.Duration(index).String()
		if _, err := service.Decide(t.Context(), "item", request, actor); err != nil {
			t.Fatalf("success %d: %v", index, err)
		}
	}
	badExpiry := valid
	badExpiry.Decision, badExpiry.ExpiresAt, badExpiry.IdempotencyKey = identitymodel.IdentityAccessReviewSetExpiry, "invalid", "bad-expiry"
	if _, err := service.Decide(t.Context(), "item", badExpiry, actor); apperror.CodeOf(err) != "backend.identity.access_review_expiry_invalid" {
		t.Fatalf("invalid expiry=%v", err)
	}
	fault.applyErr = errors.New("apply")
	applyRequest := valid
	applyRequest.IdempotencyKey = "apply-error"
	if _, err := service.Decide(t.Context(), "item", applyRequest, actor); !errors.Is(err, fault.applyErr) {
		t.Fatalf("apply error=%v", err)
	}
	fault.applyErr = nil
	fault.applyReceipt = &identitymodel.IdentityAccessReviewDecisionReceipt{Replayed: true}
	replayedApply := valid
	replayedApply.IdempotencyKey = "apply-replayed"
	if receipt, err := service.Decide(t.Context(), "item", replayedApply, actor); err != nil || !receipt.Replayed {
		t.Fatalf("replayed apply=%#v err=%v", receipt, err)
	}
	fault.applyReceipt = nil

	fault.listRolesErr = errors.New("reduction roles")
	reduction := valid
	reduction.Decision, reduction.ReplacementRoleID, reduction.IdempotencyKey = identitymodel.IdentityAccessReviewReduceScope, "reduced", "reduce-list-error"
	if _, err := service.Decide(t.Context(), "item", reduction, actor); !errors.Is(err, fault.listRolesErr) {
		t.Fatalf("reduction list error=%v", err)
	}
	fault.listRolesErr = nil
	base.roles = append(base.roles, identitymodel.IdentityRole{ID: "undefined", Key: "undefined", Status: identitymodel.IdentityStatusActive})
	reduction.ReplacementRoleID, reduction.IdempotencyKey = "undefined", "reduce-undefined"
	if _, err := service.Decide(t.Context(), "item", reduction, actor); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("undefined replacement=%v", err)
	}
	base.roles = append(base.roles, identitymodel.IdentityRole{ID: "expanded", Key: "expanded", Status: identitymodel.IdentityStatusActive})
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "current", Permissions: []string{"read", "write"}, RiskLevel: identitymodel.IdentityRoleRiskElevated},
		{Key: "reduced", Permissions: []string{"read"}, RiskLevel: identitymodel.IdentityRoleRiskNormal},
		{Key: "expanded", Permissions: []string{"read", "write", "delete"}, RiskLevel: identitymodel.IdentityRoleRiskNormal},
	})
	reduction.ReplacementRoleID, reduction.IdempotencyKey = "expanded", "reduce-expanded"
	if _, err := service.Decide(t.Context(), "item", reduction, actor); apperror.CodeOf(err) != "backend.identity.access_review_not_a_reduction" {
		t.Fatalf("expanded replacement=%v", err)
	}

	unauthorized := actor
	unauthorized.Known = false
	if _, err := service.Decide(t.Context(), "item", valid, unauthorized); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unauthorized decision=%v", err)
	}
	(*IdentityAccessReviewApplicationService)(nil).audit(t.Context(), "event", "record", actor, nil)
}

func TestAccessReviewScopeDefaultsAndWorkforceAggregation(t *testing.T) {
	actor := identitymodel.Principal{
		Known: true, UserID: "reviewer", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: identityAccessReviewTestPermissions()},
	}
	if _, err := (*IdentityAccessReviewApplicationService)(nil).ListReviews(t.Context(), "", actor); apperror.CodeOf(err) == "" {
		t.Fatalf("nil service error=%v", err)
	}
	nilIdentity := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{})
	if _, err := nilIdentity.ListReviews(t.Context(), "", actor); apperror.CodeOf(err) == "" {
		t.Fatalf("nil identity error=%v", err)
	}
	unavailable := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{
		Identity: NewIdentityApplicationService(&accessReviewUnavailableRepository{}, nil),
	})
	if _, err := unavailable.ListReviews(t.Context(), "", actor); apperror.CodeOf(err) != "backend.identity.access_review_unavailable" {
		t.Fatalf("unavailable error=%v", err)
	}
	scopeErr := errors.New("workspace scope")
	failingScope := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{
		Identity: accessReviewFailingWorkspaceScope{err: scopeErr},
	})
	if _, err := failingScope.ListReviews(t.Context(), "", actor); !errors.Is(err, scopeErr) {
		t.Fatalf("workspace scope error=%v", err)
	}

	repository := &accessReviewFaultRepository{
		identityScopedRepository: &identityScopedRepository{},
		workforceProfiles:        []identitymodel.IdentityWorkforceProfile{{ID: "profile"}},
		workforceAssignments: map[string][]identitymodel.IdentityWorkforceAssignment{
			"profile": {
				{Status: identitymodel.IdentityStatusActive, OrganizationUnitID: "org-a"},
				{Status: identitymodel.IdentityStatusActive, OrganizationUnitID: "org-a"},
				{Status: identitymodel.IdentityStatusActive, OrganizationUnitID: "org-b"},
				{Status: "inactive", OrganizationUnitID: "org-c"},
				{Status: identitymodel.IdentityStatusActive, OrganizationUnitID: " "},
			},
		},
	}
	scoped, err := NewIdentityApplicationService(repository, nil).ForWorkspace("workspace")
	if err != nil {
		t.Fatal(err)
	}
	counts, err := identityAccessReviewWorkforceAssignments(t.Context(), scoped)
	if err != nil || counts["profile"] != 2 {
		t.Fatalf("counts=%v err=%v", counts, err)
	}
	repository.listWorkforceAssignmentsErr = errors.New("assignments")
	if _, err := identityAccessReviewWorkforceAssignments(t.Context(), scoped); !errors.Is(err, repository.listWorkforceAssignmentsErr) {
		t.Fatalf("assignment error=%v", err)
	}
	repository.listWorkforceAssignmentsErr = nil
	repository.listWorkforceProfilesErr = errors.New("profiles")
	if _, err := identityAccessReviewWorkforceAssignments(t.Context(), scoped); !errors.Is(err, repository.listWorkforceProfilesErr) {
		t.Fatalf("profile error=%v", err)
	}

	defaultNow := NewIdentityAccessReviewApplicationService(IdentityAccessReviewDependencies{})
	if defaultNow.dependencies.Now == nil {
		t.Fatal("default clock was not installed")
	}
}

func identityAccessReviewTestPermissions() []string {
	return []string{
		"identity.access_reviews.create",
		"identity.access_reviews.list",
		"identity.access_review_items.decide",
	}
}
