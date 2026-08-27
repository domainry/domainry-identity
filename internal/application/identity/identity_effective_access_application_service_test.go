package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type effectiveAccessFaultRepository struct {
	*identityScopedRepository
	fail                 string
	err                  error
	userCalls            int
	roleCalls            int
	assignmentCalls      int
	failUserCall         int
	failRoleCall         int
	failAssignmentCall   int
	workforceProfiles    []identitymodel.IdentityWorkforceProfile
	workforceAssignments map[string][]identitymodel.IdentityWorkforceAssignment
}

func (r *effectiveAccessFaultRepository) GetIdentityUser(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityUser, bool, error) {
	if r.fail == "user" {
		return identitymodel.IdentityUser{}, false, r.err
	}
	return r.identityScopedRepository.GetIdentityUser(ctx, workspaceID, userID)
}

func (r *effectiveAccessFaultRepository) ListIdentityUsers(ctx context.Context, workspaceID string) ([]identitymodel.IdentityUser, error) {
	r.userCalls++
	if r.fail == "users" && (r.failUserCall == 0 || r.userCalls == r.failUserCall) {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityUsers(ctx, workspaceID)
}

func (r *effectiveAccessFaultRepository) ListIdentityRoles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityRole, error) {
	r.roleCalls++
	if r.fail == "roles" && (r.failRoleCall == 0 || r.roleCalls == r.failRoleCall) {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityRoles(ctx, workspaceID)
}

func (r *effectiveAccessFaultRepository) ListIdentityUserRoleAssignments(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	r.assignmentCalls++
	if r.fail == "assignments" && (r.failAssignmentCall == 0 || r.assignmentCalls == r.failAssignmentCall) {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityUserRoleAssignments(ctx, workspaceID, userID)
}

type effectiveAccessWorkspaceScope struct {
	identity *IdentityApplicationService
	err      error
	failAt   int
	calls    int
}

func (s *effectiveAccessWorkspaceScope) ForWorkspace(workspaceID string) (*IdentityApplicationService, error) {
	s.calls++
	if s.err != nil && (s.failAt == 0 || s.calls == s.failAt) {
		return nil, s.err
	}
	return s.identity.ForWorkspace(workspaceID)
}

func (r *effectiveAccessFaultRepository) ListIdentityMenus(ctx context.Context, workspaceID string) ([]identitymodel.IdentityMenu, error) {
	if r.fail == "menus" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityMenus(ctx, workspaceID)
}

func (r *effectiveAccessFaultRepository) ListIdentityRoleMenuAssignments(ctx context.Context, workspaceID, roleID string) ([]identitymodel.IdentityRoleMenuAssignment, error) {
	if r.fail == "role menus" {
		return nil, r.err
	}
	return r.identityScopedRepository.ListIdentityRoleMenuAssignments(ctx, workspaceID, roleID)
}

func (r *effectiveAccessFaultRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	if r.fail == "workforce profiles" {
		return nil, r.err
	}
	return r.workforceProfiles, nil
}

func (r *effectiveAccessFaultRepository) GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return identitymodel.IdentityWorkforceProfile{}, false, nil
}

func (r *effectiveAccessFaultRepository) UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error {
	return nil
}

func (r *effectiveAccessFaultRepository) ListIdentityWorkforceAssignments(_ context.Context, _, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	return r.workforceAssignments[profileID], nil
}

func (r *effectiveAccessFaultRepository) GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return identitymodel.IdentityWorkforceAssignment{}, false, nil
}

func (r *effectiveAccessFaultRepository) UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error {
	return nil
}

func TestIdentityEffectiveAccessSnapshotAndExplainPublishStableGrantSources(t *testing.T) {
	repository := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "operator-id", Key: "operator", Label: "Operator", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{
			UserID: "target", RoleID: "operator-id", Source: "manual", ValidFrom: "2026-07-01T00:00:00Z",
		}},
		menus:     []identitymodel.IdentityMenu{{ID: "orders", Key: "orders", Status: identitymodel.IdentityStatusActive}},
		roleMenus: []identitymodel.IdentityRoleMenuAssignment{{RoleID: "operator-id", MenuID: "orders"}},
	}
	identity := NewIdentityApplicationService(repository, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "operator", PermissionSetKeys: []string{"order_reader"}, GuardrailKeys: []string{"protect_secret"},
		Permissions: []string{"order.read"}, DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "department", Read: true}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "number", Read: true}},
		Guardrails: []identitymodel.IdentityGuardrailPolicy{{Key: "protect_secret", FieldRestrictions: []identitymodel.IdentityFieldRestriction{{
			ObjectKey: "order", FieldKey: "secret", Actions: []string{"read", "export"},
		}}}},
	}})
	identity.ReplaceAuthorizationCatalogs(
		[]identitymodel.IdentityPermissionSet{{Key: "order_reader", Permissions: []string{"order.read"}}},
		nil,
		[]identitymodel.IdentityGuardrailPolicy{{Key: "protect_secret"}},
	)
	objects := []definitionmodel.ObjectSchema{{Key: "order", Fields: []definitionmodel.FieldSchema{
		{Key: "number", Type: "text"},
		{Key: "secret", Type: "text", Config: map[string]any{"sensitivity": "secret"}},
	}}}
	service := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity, Objects: func() []definitionmodel.ObjectSchema { return objects },
		RecordScopeAllows: func(context.Context, string, string, string, identitymodel.Principal) (bool, error) {
			return false, nil
		},
	})
	admin := identitymodel.Principal{Known: true, UserID: "admin", WorkspaceID: "workspace-a", Role: identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}}}
	snapshot, err := service.Snapshot(t.Context(), "target", admin)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Known || snapshot.AuthorizationRevision == "" || len(snapshot.RoleAssignments) != 1 || len(snapshot.PermissionSetKeys) != 1 ||
		snapshot.PermissionSetKeys[0] != "order_reader" || len(snapshot.GuardrailKeys) != 1 || len(snapshot.Permissions) != 1 ||
		len(snapshot.Permissions[0].Sources) == 0 || len(snapshot.Menus) != 1 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	allowed, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{UserID: "target", ObjectKey: "order", Action: "read", FieldKey: "number"}, admin)
	if err != nil || !allowed.Allowed || allowed.Reason.Code != "effective_access_allowed" || len(allowed.Reason.Children) != 3 {
		t.Fatalf("allowed explain=%#v err=%v", allowed, err)
	}
	denied, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{UserID: "target", ObjectKey: "order", Action: "read", FieldKey: "secret"}, admin)
	if err != nil || denied.Allowed || denied.Reason.Code != "guardrail_field_denied" {
		t.Fatalf("denied explain=%#v err=%v", denied, err)
	}
	recordDenied, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{UserID: "target", ObjectKey: "order", Action: "read", FieldKey: "number", RecordID: "order-secret-value"}, admin)
	raw, marshalErr := json.Marshal(recordDenied)
	if err != nil || marshalErr != nil || recordDenied.Allowed || recordDenied.Reason.Code != "record_scope_denied" || strings.Contains(string(raw), "claim") || strings.Contains(string(raw), "record_data") {
		t.Fatalf("record explain=%#v raw=%s err=%v marshal=%v", recordDenied, raw, err, marshalErr)
	}
}

func TestIdentityEffectiveAccessExplainResolvesNamespacedPermissionAndGrantSource(t *testing.T) {
	repository := &identityScopedRepository{
		users:       []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles:       []identitymodel.IdentityRole{{ID: "operator-id", Key: "operator", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "target", RoleID: "operator-id", Source: "manual"}},
	}
	identity := NewIdentityApplicationService(repository, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "operator", Permissions: []string{"crm.order.read"},
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "all_records", Read: true}},
	}})
	service := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity, Objects: func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{{Key: "order"}} },
	})
	admin := identitymodel.Principal{Known: true, UserID: "admin", WorkspaceID: "workspace-a", Role: identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}}}
	result, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{UserID: "target", ObjectKey: "order", Action: "read"}, admin)
	if err != nil || !result.Allowed || len(result.Reason.Children) < 1 || len(result.Reason.Children[0].Sources) != 1 {
		t.Fatalf("namespaced permission explain=%#v err=%v", result, err)
	}
	if result.Reason.Children[0].Sources[0].RoleKey != "operator" {
		t.Fatalf("namespaced grant source=%#v", result.Reason.Children[0].Sources)
	}
}

func TestIdentityEffectiveAccessRejectsCrossUserReaderWithoutGovernancePermission(t *testing.T) {
	service := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{Identity: NewIdentityApplicationService(&identityScopedRepository{}, nil), Objects: func() []definitionmodel.ObjectSchema { return nil }})
	actor := identitymodel.Principal{Known: true, UserID: "reader", WorkspaceID: "workspace-a"}
	if _, err := service.Snapshot(t.Context(), "other", actor); err == nil {
		t.Fatal("cross-user effective access was exposed without governance permission")
	}
	if _, err := service.Snapshot(t.Context(), "reader", actor); err != nil {
		t.Fatalf("self effective access rejected: %v", err)
	}
}

func TestIdentityEffectiveAccessGovernanceSurfacesAndPreview(t *testing.T) {
	base := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "role-id", Key: "operator", Status: identitymodel.IdentityStatusActive},
			{ID: "role-by-id", Key: "reader", Status: identitymodel.IdentityStatusActive},
		},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "target", RoleID: "role-id", Source: "manual", Status: "active"}},
	}
	repository := &effectiveAccessFaultRepository{
		identityScopedRepository: base,
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{
			{ID: "active-profile", WorkStatus: identitymodel.IdentityWorkActive},
			{ID: "inactive-profile", WorkStatus: "inactive"},
		},
	}
	identity := NewIdentityApplicationService(repository, []identitymodel.IdentityPermissionDefinition{{Key: "order.read"}})
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "operator", Permissions: []string{"order.read"}},
		{Key: "reader", Permissions: []string{"order.read"}},
	})
	service := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity,
		Objects:  func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{{Key: "order"}} },
		Actions:  func() []definitionmodel.ActionSchema { return []definitionmodel.ActionSchema{{Key: "approve"}} },
	})
	admin := identitymodel.Principal{
		Known: true, UserID: "admin", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}},
	}
	if reverse, err := service.ReverseIndex(t.Context(), admin); err != nil || len(reverse.RolePermissions) == 0 {
		t.Fatalf("reverse=%#v err=%v", reverse, err)
	}
	if reports, err := service.GovernanceReports(t.Context(), admin); err != nil || reports.OrphanPermissions == nil {
		t.Fatalf("reports=%#v err=%v", reports, err)
	}
	withoutWorkforce := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: NewIdentityApplicationService(base, nil),
		Objects:  func() []definitionmodel.ObjectSchema { return nil },
	})
	if _, err := withoutWorkforce.GovernanceReports(t.Context(), admin); err != nil {
		t.Fatalf("unavailable workforce should be optional: %v", err)
	}
	preview, err := service.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{
		Role: identitymodel.RoleSchema{Key: "operator", Permissions: []string{"order.read", "order.write"}},
	}, admin)
	if err != nil || preview.RoleKey != "operator" {
		t.Fatalf("preview=%#v err=%v", preview, err)
	}
	preview, err = service.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{
		RoleKey: "role-by-id", Role: identitymodel.RoleSchema{Key: "reader"},
	}, admin)
	if err != nil || preview.RoleKey != "role-by-id" {
		t.Fatalf("id preview=%#v err=%v", preview, err)
	}
	if _, err := service.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{RoleKey: "missing"}, admin); apperror.CodeOf(err) != "backend.identity.role_not_found" {
		t.Fatalf("missing preview error=%v", err)
	}
	noActions := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity, Objects: func() []definitionmodel.ObjectSchema { return nil },
	})
	if _, err := noActions.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{RoleKey: "operator"}, admin); err == nil {
		t.Fatal("nil actions dependency was accepted")
	}

	outsider := admin
	outsider.Role = identitymodel.RoleSchema{}
	if _, err := service.ReverseIndex(t.Context(), outsider); apperror.CodeOf(err) != "backend.permission.denied" {
		t.Fatalf("outsider reverse error=%v", err)
	}
	unknown := admin
	unknown.Known = false
	if _, err := service.GovernanceReports(t.Context(), unknown); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unknown governance error=%v", err)
	}
	if _, err := service.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{RoleKey: "operator"}, outsider); apperror.CodeOf(err) != "backend.permission.denied" {
		t.Fatalf("outsider preview error=%v", err)
	}
	if _, err := (*IdentityEffectiveAccessApplicationService)(nil).ReverseIndex(t.Context(), admin); err == nil {
		t.Fatal("nil governance service was accepted")
	}
	for name, dependencies := range map[string]IdentityEffectiveAccessDependencies{
		"identity": {Objects: func() []definitionmodel.ObjectSchema { return nil }},
		"objects":  {Identity: identity},
	} {
		if _, err := NewIdentityEffectiveAccessApplicationService(dependencies).ReverseIndex(t.Context(), admin); err == nil {
			t.Fatalf("nil %s dependency was accepted", name)
		}
	}
	if _, err := (*IdentityEffectiveAccessApplicationService)(nil).Snapshot(t.Context(), "target", admin); err == nil {
		t.Fatal("nil snapshot service was accepted")
	}
	for name, dependencies := range map[string]IdentityEffectiveAccessDependencies{
		"identity": {Objects: func() []definitionmodel.ObjectSchema { return nil }},
		"objects":  {Identity: identity},
	} {
		if _, err := NewIdentityEffectiveAccessApplicationService(dependencies).Snapshot(t.Context(), "target", admin); err == nil {
			t.Fatalf("snapshot nil %s dependency was accepted", name)
		}
	}
	if _, err := service.Snapshot(t.Context(), "target", unknown); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unknown snapshot error=%v", err)
	}
}

func TestIdentityEffectiveAccessPropagatesRepositoryAndRecordScopeFailures(t *testing.T) {
	expected := errors.New("injected")
	base := &identityScopedRepository{
		users:       []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles:       []identitymodel.IdentityRole{{ID: "role", Key: "operator", Status: identitymodel.IdentityStatusActive}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "target", RoleID: "role", Status: "active"}},
		menus:       []identitymodel.IdentityMenu{{ID: "menu", Key: "menu", Status: identitymodel.IdentityStatusActive}},
	}
	repository := &effectiveAccessFaultRepository{identityScopedRepository: base, err: expected}
	identity := NewIdentityApplicationService(repository, nil)
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "operator", Permissions: []string{"order.read"},
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "all_records", Read: true}},
	}})
	objects := func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{{Key: "order"}} }
	admin := identitymodel.Principal{
		Known: true, UserID: "admin", WorkspaceID: "workspace",
		Role: identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}},
	}
	service := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{Identity: identity, Objects: objects, Actions: func() []definitionmodel.ActionSchema { return nil }})

	for _, fail := range []string{"roles", "assignments"} {
		repository.fail = fail
		if _, err := service.ReverseIndex(t.Context(), admin); !errors.Is(err, expected) {
			t.Fatalf("reverse %s error=%v", fail, err)
		}
	}
	for _, fail := range []string{"roles", "assignments", "workforce profiles"} {
		repository.fail = fail
		if _, err := service.GovernanceReports(t.Context(), admin); !errors.Is(err, expected) {
			t.Fatalf("reports %s error=%v", fail, err)
		}
	}
	for _, fail := range []string{"roles", "assignments"} {
		repository.fail = fail
		if _, err := service.PreviewRoleChange(t.Context(), identitymodel.IdentityRoleChangeImpactRequest{RoleKey: "operator"}, admin); !errors.Is(err, expected) {
			t.Fatalf("preview %s error=%v", fail, err)
		}
	}
	for _, fail := range []string{"users", "assignments", "roles", "menus", "role menus"} {
		repository.userCalls, repository.assignmentCalls, repository.roleCalls = 0, 0, 0
		repository.failUserCall, repository.failAssignmentCall, repository.failRoleCall = 0, 0, 0
		repository.fail = fail
		if _, err := service.Snapshot(t.Context(), "target", admin); !errors.Is(err, expected) {
			t.Fatalf("snapshot %s error=%v", fail, err)
		}
	}
	repository.fail = "assignments"
	repository.assignmentCalls, repository.failAssignmentCall = 0, 2
	if _, err := service.Snapshot(t.Context(), "target", admin); !errors.Is(err, expected) {
		t.Fatalf("effective assignment error=%v", err)
	}
	repository.fail = "roles"
	repository.roleCalls, repository.failRoleCall = 0, 2
	if _, err := service.Snapshot(t.Context(), "target", admin); !errors.Is(err, expected) {
		t.Fatalf("snapshot role-list error=%v", err)
	}
	repository.fail = ""
	repository.failAssignmentCall, repository.failRoleCall = 0, 0

	firstScopeErr := errors.New("first workspace scope")
	firstScope := &effectiveAccessWorkspaceScope{identity: identity, err: firstScopeErr, failAt: 1}
	scopeService := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: firstScope, Objects: objects, Actions: func() []definitionmodel.ActionSchema { return nil },
	})
	if _, err := scopeService.ReverseIndex(t.Context(), admin); !errors.Is(err, firstScopeErr) {
		t.Fatalf("governance workspace scope error=%v", err)
	}
	firstScope.calls = 0
	if _, err := scopeService.Snapshot(t.Context(), "target", admin); !errors.Is(err, firstScopeErr) {
		t.Fatalf("snapshot workspace scope error=%v", err)
	}

	secondScopeErr := errors.New("second workspace scope")
	secondScope := &effectiveAccessWorkspaceScope{identity: identity, err: secondScopeErr, failAt: 2}
	secondScopeService := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: secondScope, Objects: objects,
	})
	if _, err := secondScopeService.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{
		UserID: "target", ObjectKey: "order", Action: "read",
	}, admin); !errors.Is(err, secondScopeErr) {
		t.Fatalf("explain workspace scope error=%v", err)
	}

	repository.fail = "users"
	repository.userCalls, repository.failUserCall = 0, 2
	if _, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{
		UserID: "target", ObjectKey: "order", Action: "read",
	}, admin); !errors.Is(err, expected) {
		t.Fatalf("explain principal error=%v", err)
	}
	repository.fail, repository.failUserCall = "", 0
	unknown := admin
	unknown.Known = false
	if _, err := service.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{UserID: "target"}, unknown); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("explain snapshot authorization error=%v", err)
	}

	nilScope := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{Identity: identity, Objects: objects})
	if _, err := nilScope.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{
		UserID: "target", ObjectKey: "order", Action: "read", RecordID: "record",
	}, admin); err == nil {
		t.Fatal("nil record scope dependency was accepted")
	}
	errorScope := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity, Objects: objects,
		RecordScopeAllows: func(context.Context, string, string, string, identitymodel.Principal) (bool, error) {
			return false, expected
		},
	})
	if _, err := errorScope.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{
		UserID: "target", ObjectKey: "order", Action: "read", RecordID: "record",
	}, admin); !errors.Is(err, expected) {
		t.Fatalf("record scope error=%v", err)
	}
	allowScope := NewIdentityEffectiveAccessApplicationService(IdentityEffectiveAccessDependencies{
		Identity: identity, Objects: objects,
		RecordScopeAllows: func(context.Context, string, string, string, identitymodel.Principal) (bool, error) {
			return true, nil
		},
	})
	result, err := allowScope.Explain(t.Context(), identitymodel.IdentityAccessExplainRequest{
		UserID: "target", ObjectKey: "order", Action: "read", RecordID: "record",
	}, admin)
	if err != nil || !result.Allowed || result.Reason.Children[len(result.Reason.Children)-1].Code != "record_scope_allowed" {
		t.Fatalf("allowed record scope=%#v err=%v", result, err)
	}
}
