package service

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"testing"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityPrincipalRoleRepository struct {
	*identityRolesRepositoryStub
	permissionAssignments   []identitymodel.IdentityRolePermissionAssignment
	dataScopes              []identitymodel.IdentityDataScopePolicy
	fieldPermissions        []identitymodel.IdentityFieldPermission
	permissionErr           error
	dataScopeErr            error
	fieldPermissionErr      error
	listUsersCalls          int
	listUsersFailAt         int
	listRolesCalls          int
	listRolesFailAt         int
	listAssignmentsCalls    int
	listAssignmentsFailAt   int
	permissionCalls         int
	permissionFailAt        int
	dataScopeCalls          int
	dataScopeFailAt         int
	fieldPermissionCalls    int
	fieldPermissionFailAt   int
	workforceProfiles       []identitymodel.IdentityWorkforceProfile
	workforceAssignments    []identitymodel.IdentityWorkforceAssignment
	workforceProfilesErr    error
	workforceAssignmentsErr error
	departmentsErr          error
	workforceEntries        []identitymodel.IdentityWorkforceDirectoryEntry
}

func (r *identityPrincipalRoleRepository) ListIdentityUsers(ctx context.Context, workspace string) ([]identitymodel.IdentityUser, error) {
	_, _ = ctx, workspace
	r.listUsersCalls++
	if r.listUsersFailAt == r.listUsersCalls {
		return nil, r.listUsersErr
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}

func (r *identityPrincipalRoleRepository) ListIdentityRoles(context.Context, string) ([]identitymodel.IdentityRole, error) {
	r.listRolesCalls++
	if r.listRolesErr != nil && (r.listRolesFailAt == 0 || r.listRolesFailAt == r.listRolesCalls) {
		return nil, r.listRolesErr
	}
	return append([]identitymodel.IdentityRole(nil), r.roles...), nil
}

func (r *identityPrincipalRoleRepository) ListIdentityUserRoleAssignments(context.Context, string, string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	r.listAssignmentsCalls++
	if r.listAssignmentsErr != nil && (r.listAssignmentsFailAt == 0 || r.listAssignmentsFailAt == r.listAssignmentsCalls) {
		return nil, r.listAssignmentsErr
	}
	return append([]identitymodel.IdentityUserRoleAssignment(nil), r.assignments...), nil
}

func (r *identityPrincipalRoleRepository) ListIdentityWorkforceProfiles(context.Context, string) ([]identitymodel.IdentityWorkforceProfile, error) {
	if r.workforceProfilesErr != nil {
		return nil, r.workforceProfilesErr
	}
	if r.workforceProfiles != nil {
		return append([]identitymodel.IdentityWorkforceProfile(nil), r.workforceProfiles...), nil
	}
	out := []identitymodel.IdentityWorkforceProfile{}
	for _, entry := range r.workforceEntries {
		out = append(out, identitymodel.IdentityWorkforceProfile{
			ID: entry.WorkforceProfileID, OrganizationID: "organization", IdentityUserID: entry.IdentityUserID,
			WorkerNo: entry.IdentityUserID, WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
			PrimaryAssignmentID: entry.WorkforceProfileID + "-primary",
		})
	}
	return out, nil
}

func (r *identityPrincipalRoleRepository) GetIdentityWorkforceProfile(context.Context, string, string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	return identitymodel.IdentityWorkforceProfile{}, false, nil
}

func (r *identityPrincipalRoleRepository) UpsertIdentityWorkforceProfile(context.Context, string, identitymodel.IdentityWorkforceProfile) error {
	return nil
}

func (r *identityPrincipalRoleRepository) ListIdentityWorkforceAssignments(context.Context, string, string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	if r.workforceAssignmentsErr != nil {
		return nil, r.workforceAssignmentsErr
	}
	if r.workforceAssignments != nil {
		return append([]identitymodel.IdentityWorkforceAssignment(nil), r.workforceAssignments...), nil
	}
	out := []identitymodel.IdentityWorkforceAssignment{}
	profileByUser := map[string]string{}
	for _, entry := range r.workforceEntries {
		profileByUser[entry.IdentityUserID] = entry.WorkforceProfileID
	}
	for _, entry := range r.workforceEntries {
		managerProfileID := ""
		if entry.ManagerIdentityUserID != "" {
			managerProfileID = profileByUser[entry.ManagerIdentityUserID]
		}
		out = append(out, identitymodel.IdentityWorkforceAssignment{
			ID: entry.WorkforceProfileID + "-primary", WorkforceProfileID: entry.WorkforceProfileID,
			OrganizationUnitID: entry.OrganizationUnitID, ManagerWorkforceProfileID: managerProfileID,
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive,
		})
	}
	return out, nil
}

func (r *identityPrincipalRoleRepository) GetIdentityWorkforceAssignment(context.Context, string, string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	return identitymodel.IdentityWorkforceAssignment{}, false, nil
}

func (r *identityPrincipalRoleRepository) UpsertIdentityWorkforceAssignment(context.Context, string, identitymodel.IdentityWorkforceAssignment) error {
	return nil
}

func (r *identityPrincipalRoleRepository) ListIdentityDepartments(context.Context, string) ([]identitymodel.IdentityDepartment, error) {
	if r.departmentsErr != nil {
		return nil, r.departmentsErr
	}
	byID := map[string]string{}
	for _, entry := range r.workforceEntries {
		if entry.OrganizationUnitID != "" {
			byID[entry.OrganizationUnitID] = entry.OrganizationPath
		}
	}
	out := make([]identitymodel.IdentityDepartment, 0, len(byID))
	for id, path := range byID {
		out = append(out, identitymodel.IdentityDepartment{ID: id, Path: path, Status: identitymodel.IdentityStatusActive})
	}
	return out, nil
}

func (r *identityPrincipalRoleRepository) ListIdentityRolePermissionAssignments(context.Context, string, string) ([]identitymodel.IdentityRolePermissionAssignment, error) {
	r.permissionCalls++
	if r.permissionErr != nil && (r.permissionFailAt == 0 || r.permissionFailAt == r.permissionCalls) {
		return nil, r.permissionErr
	}
	return append([]identitymodel.IdentityRolePermissionAssignment(nil), r.permissionAssignments...), nil
}

func (r *identityPrincipalRoleRepository) ListIdentityRoleDataScopes(context.Context, string, string) ([]identitymodel.IdentityDataScopePolicy, error) {
	r.dataScopeCalls++
	if r.dataScopeErr != nil && (r.dataScopeFailAt == 0 || r.dataScopeFailAt == r.dataScopeCalls) {
		return nil, r.dataScopeErr
	}
	return append([]identitymodel.IdentityDataScopePolicy(nil), r.dataScopes...), nil
}

func (r *identityPrincipalRoleRepository) ListIdentityRoleFieldPermissions(context.Context, string, string) ([]identitymodel.IdentityFieldPermission, error) {
	r.fieldPermissionCalls++
	if r.fieldPermissionErr != nil && (r.fieldPermissionFailAt == 0 || r.fieldPermissionFailAt == r.fieldPermissionCalls) {
		return nil, r.fieldPermissionErr
	}
	return append([]identitymodel.IdentityFieldPermission(nil), r.fieldPermissions...), nil
}

func TestBuildPrincipalForRoleUsesOnlyPublishedRolePolicy(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			roles: []identitymodel.IdentityRole{{
				ID: "role-1", Status: identitymodel.IdentityStatusActive,
			}},
			users: []identitymodel.IdentityUser{
				{ID: "user-1", Status: identitymodel.IdentityStatusActive},
				{ID: "report-b", Status: identitymodel.IdentityStatusActive},
				{ID: "report-a", Status: identitymodel.IdentityStatusActive},
				{ID: "outside", Status: identitymodel.IdentityStatusActive},
			},
			assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-1"}},
		},
		workforceEntries: []identitymodel.IdentityWorkforceDirectoryEntry{
			{WorkforceProfileID: "user-workforce", IdentityUserID: "user-1", OrganizationUnitID: "department-1", OrganizationPath: "/company/sales"},
			{WorkforceProfileID: "report-b-workforce", IdentityUserID: "report-b", ManagerIdentityUserID: "user-1"},
			{WorkforceProfileID: "report-a-workforce", IdentityUserID: "report-a", ManagerIdentityUserID: "user-1"},
			{WorkforceProfileID: "outside-workforce", IdentityUserID: "outside"},
		},
		permissionAssignments: []identitymodel.IdentityRolePermissionAssignment{{RoleID: "role-1", PermissionKey: "b.permission"}, {RoleID: "role-1", PermissionKey: " "}},
		dataScopes:            []identitymodel.IdentityDataScopePolicy{{Resource: "order", Scope: identitymodel.IdentityDataScope("owned_records")}},
		fieldPermissions:      []identitymodel.IdentityFieldPermission{{Resource: "order", Field: "amount", Visible: true, Masked: true}},
	}
	service := principalRoleService(t, repository)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "role-1", Name: "role-1", Permissions: []string{"a.permission", "b.permission", "z.permission"}, RecordScope: "all_records",
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true, Write: true}, {ObjectKey: "order", Scope: "owned_records", Read: true, Write: true}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "name", Read: true, Write: true}, {ObjectKey: "order", FieldKey: "amount", Read: true, Masked: true}},
	}})
	principal, err := service.BuildPrincipalForRole(t.Context(), "user-1", "role-1")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.UserID != "user-1" || principal.WorkspaceID != "workspace-1" || principal.DepartmentID != "department-1" || principal.Role.Key != "role-1" || principal.Role.Name != "role-1" {
		t.Fatalf("principal=%#v", principal)
	}
	if want := []string{"a.permission", "b.permission", "z.permission"}; !reflect.DeepEqual(principal.Role.Permissions, want) {
		t.Fatalf("permissions=%v want=%v", principal.Role.Permissions, want)
	}
	if len(principal.Role.DataPermissions) != 2 || principal.Role.DataPermissions[1].ObjectKey != "order" || len(principal.Role.FieldPermissions) != 2 || principal.Role.FieldPermissions[1].FieldKey != "amount" || !principal.Role.FieldPermissions[1].Masked {
		t.Fatalf("role policy=%#v", principal.Role)
	}
	if want := []string{"report-a", "report-b"}; !reflect.DeepEqual(principal.ReportingUserIDs, want) {
		t.Fatalf("reporting users=%v want=%v", principal.ReportingUserIDs, want)
	}
}

func TestBuildPrincipalEffectiveAuthorizationIsIndependentOfRoleOrder(t *testing.T) {
	roles := []identitymodel.IdentityRole{
		{ID: "role-a", Key: "role-a", Status: identitymodel.IdentityStatusActive},
		{ID: "role-b", Key: "role-b", Status: identitymodel.IdentityStatusActive},
		{ID: "role-c", Key: "role-c", Status: identitymodel.IdentityStatusActive},
	}
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "role-a"},
		{UserID: "user-1", RoleID: "role-b"},
		{UserID: "user-1", RoleID: "role-c"},
	}
	definitions := []identitymodel.RoleSchema{
		{
			Key: "role-a", Permissions: []string{"invoice.read"},
			DataPermissions:      []identitymodel.DataPermission{{ObjectKey: "invoice", Scope: "owned_records", Read: true}},
			FieldPermissions:     []identitymodel.FieldPermission{{ObjectKey: "invoice", FieldKey: "number", Read: true}},
			ReferencePermissions: []identitymodel.ReferencePermission{{SourceObjectKey: "invoice", RelationFieldKey: "customer_id", TargetObjectKey: "customer", DisplayFields: []string{"name"}}},
			ExportRules:          []identitymodel.ExportRule{{ObjectKey: "invoice", Mode: "allow_list", Fields: []string{"number"}}},
		},
		{
			Key: "role-b", Permissions: []string{"invoice.update"},
			DataPermissions:      []identitymodel.DataPermission{{ObjectKey: "invoice", Scope: "department", Read: true, Write: true}},
			FieldPermissions:     []identitymodel.FieldPermission{{ObjectKey: "invoice", FieldKey: "status", Read: true, Write: true}},
			ReferencePermissions: []identitymodel.ReferencePermission{{SourceObjectKey: "invoice", RelationFieldKey: "owner_id", TargetObjectKey: "identity_user", DisplayFields: []string{"name"}}},
			ExportRules:          []identitymodel.ExportRule{{ObjectKey: "invoice", Mode: "deny"}},
		},
		{
			Key: "role-c", Permissions: []string{"invoice.export"},
			DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true}},
			FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "name", Read: true, Export: true}},
			ExportRules:      []identitymodel.ExportRule{{ObjectKey: "customer", Mode: "allow_list", Fields: []string{"name"}}},
		},
	}
	repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
		users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
	}}
	service := principalRoleService(t, repository)
	service.ReplaceRoleDefinitions(definitions)

	random := rand.New(rand.NewSource(42))
	var expected []byte
	var expectedDecisions []bool
	for iteration := 0; iteration < 10_000; iteration++ {
		repository.roles = append(repository.roles[:0], roles...)
		random.Shuffle(len(repository.roles), func(left, right int) {
			repository.roles[left], repository.roles[right] = repository.roles[right], repository.roles[left]
		})
		repository.assignments = append(repository.assignments[:0], assignments...)
		random.Shuffle(len(repository.assignments), func(left, right int) {
			repository.assignments[left], repository.assignments[right] = repository.assignments[right], repository.assignments[left]
		})
		principal, err := service.BuildPrincipal(t.Context(), "user-1")
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := json.Marshal(principal.Role)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			expected = snapshot
			expectedDecisions = effectiveAuthorizationDecisionVector(principal.Role)
			continue
		}
		if !reflect.DeepEqual(snapshot, expected) {
			t.Fatalf("iteration %d produced order-dependent authorization\n got: %s\nwant: %s", iteration, snapshot, expected)
		}
		if decisions := effectiveAuthorizationDecisionVector(principal.Role); !reflect.DeepEqual(decisions, expectedDecisions) {
			t.Fatalf("iteration %d produced order-dependent authorization decisions: got=%v want=%v", iteration, decisions, expectedDecisions)
		}
	}
}

func TestAuthorizationRevisionChangesForAssignmentWorkforcePermissionSetAndGuardrailFacts(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users: []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
			roles: []identitymodel.IdentityRole{
				{ID: "operator", Key: "operator", Status: identitymodel.IdentityStatusActive},
				{ID: "reviewer", Key: "reviewer", Status: identitymodel.IdentityStatusActive},
			},
			assignments: []identitymodel.IdentityUserRoleAssignment{{
				UserID: "user-1", RoleID: "operator", WorkforceProfileID: "worker-1", UpdatedAt: "2026-07-25T01:00:00Z",
			}},
		},
		workforceProfiles: []identitymodel.IdentityWorkforceProfile{{
			ID: "worker-1", IdentityUserID: "user-1", WorkStatus: identitymodel.IdentityWorkActive,
			PrimaryAssignmentID: "assignment-1", Version: 1,
		}},
		workforceAssignments: []identitymodel.IdentityWorkforceAssignment{{
			ID: "assignment-1", WorkforceProfileID: "worker-1", OrganizationUnitID: "sales",
			AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary, Status: identitymodel.IdentityStatusActive, Version: 1,
		}},
		workforceEntries: []identitymodel.IdentityWorkforceDirectoryEntry{{OrganizationUnitID: "sales", OrganizationPath: "/company/sales"}},
	}
	service := principalRoleService(t, repository)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "operator", Permissions: []string{"order.read"}, DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "department", Read: true}}},
		{Key: "reviewer", Permissions: []string{"order.review"}},
	})

	revision := func() string {
		principal, err := service.BuildPrincipal(t.Context(), "user-1")
		if err != nil {
			t.Fatal(err)
		}
		if principal.AuthorizationRevision == "" {
			t.Fatal("known principal has no authorization revision")
		}
		return principal.AuthorizationRevision
	}
	assertChanged := func(label, previous string) string {
		t.Helper()
		current := revision()
		if current == previous {
			t.Fatalf("%s did not change authorization revision", label)
		}
		return current
	}

	current := revision()
	repository.assignments[0].UpdatedAt = "2026-07-25T01:01:00Z"
	current = assertChanged("role assignment", current)
	repository.workforceAssignments[0].Version++
	current = assertChanged("workforce assignment", current)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{
			Key: "operator", Permissions: []string{"order.read", "order.export"},
			DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "department", Read: true}},
		},
		{Key: "reviewer", Permissions: []string{"order.review"}},
	})
	current = assertChanged("expanded permission set", current)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{
			Key: "operator", Permissions: []string{"order.read", "order.export"},
			DataPermissions: []identitymodel.DataPermission{{ObjectKey: "order", Scope: "department", Read: true}},
			Guardrails: []identitymodel.IdentityGuardrailPolicy{{
				Key: "no-export", DeniedPermissionKeys: []string{"order.export"},
			}},
		},
		{Key: "reviewer", Permissions: []string{"order.review"}},
	})
	current = assertChanged("guardrail", current)
	repository.assignments = append(repository.assignments, identitymodel.IdentityUserRoleAssignment{UserID: "user-1", RoleID: "reviewer"})
	assertChanged("role membership", current)
}

func effectiveAuthorizationDecisionVector(role identitymodel.RoleSchema) []bool {
	return []bool{
		identitycontract.IdentityRoleAllowsData(role, "invoice", "read"),
		identitycontract.IdentityRoleAllowsData(role, "invoice", "update"),
		identitycontract.IdentityDataScopeForAction(role, "invoice", "read") == "department",
		identitycontract.IdentityCanReadField(role, "invoice", "number"),
		identitycontract.IdentityCanWriteField(role, "invoice", "status"),
		identitycontract.IdentityCanExportField(role, "customer", "name"),
	}
}

func TestBuildPrincipalForRoleMatchesKeyAndHandlesUnknownIdentity(t *testing.T) {
	repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
		roles: []identitymodel.IdentityRole{
			{ID: "disabled", Key: "operator", Status: identitymodel.IdentityStatusDisabled},
			{ID: "active", Key: "operator", Label: "Operator", Status: identitymodel.IdentityStatusActive},
		},
		users:       []identitymodel.IdentityUser{{ID: "admin", Status: identitymodel.IdentityStatusActive}, {ID: "inactive", Status: identitymodel.IdentityStatusDisabled}},
		assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "admin", RoleID: "active"}},
	}}
	service := principalRoleService(t, repository)
	principal, err := service.BuildPrincipalForRole(t.Context(), "", " operator ")
	if err != nil || !principal.Known || principal.UserID != "admin" || principal.Role.Key != "operator" || principal.Role.Name != "Operator" {
		t.Fatalf("principal=%#v err=%v", principal, err)
	}
	for _, request := range []struct{ userID, roleKey string }{{"missing", "operator"}, {"inactive", "operator"}, {"admin", " "}, {"admin", "missing"}} {
		principal, err := service.BuildPrincipalForRole(t.Context(), request.userID, request.roleKey)
		if err != nil || principal.Known {
			t.Fatalf("request=%+v principal=%#v err=%v", request, principal, err)
		}
	}
}

func TestBuildPrincipalForRolePropagatesRepositoryFailures(t *testing.T) {
	failure := errors.New("identity principal repository failure")
	tests := []struct {
		name      string
		configure func(*identityPrincipalRoleRepository)
	}{
		{name: "get user", configure: func(repository *identityPrincipalRoleRepository) {
			repository.listUsersErr = failure
			repository.listUsersFailAt = 1
		}},
		{name: "list roles", configure: func(repository *identityPrincipalRoleRepository) { repository.listRolesErr = failure }},
		{name: "workforce profiles", configure: func(repository *identityPrincipalRoleRepository) {
			repository.workforceProfilesErr = failure
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
				roles:       []identitymodel.IdentityRole{{ID: "role-1", Key: "member", Status: identitymodel.IdentityStatusActive}},
				users:       []identitymodel.IdentityUser{{ID: "user-1", Status: identitymodel.IdentityStatusActive}},
				assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user-1", RoleID: "role-1"}},
			}}
			test.configure(repository)
			service := principalRoleService(t, repository)
			if _, err := service.BuildPrincipalForRole(t.Context(), "user-1", "member"); !errors.Is(err, failure) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func principalRoleService(t *testing.T, repository *identityPrincipalRoleRepository) *IdentityDomainService {
	t.Helper()
	service, err := NewIdentityDomainService(repository, nil).ForWorkspace("workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	definitions := make([]identitymodel.RoleSchema, 0, len(repository.roles))
	for _, role := range repository.roles {
		key := valueOrDefault(role.Key, role.ID)
		definitions = append(definitions, identitymodel.RoleSchema{Key: key, Name: valueOrDefault(role.Label, key), RecordScope: "all_records"})
	}
	service.ReplaceRoleDefinitions(definitions)
	return service
}
