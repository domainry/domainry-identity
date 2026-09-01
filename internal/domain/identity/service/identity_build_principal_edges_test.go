package service

import (
	"errors"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestBuildPrincipalEffectiveRoleAndReportingEdges(t *testing.T) {
	expired := "2000-01-01T00:00:00Z"
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			roles: []identitymodel.IdentityRole{
				{ID: "role-one", Status: identitymodel.IdentityStatusActive},
				{ID: "role-disabled", Status: identitymodel.IdentityStatusDisabled},
				{ID: "role-unassigned", Status: identitymodel.IdentityStatusActive},
			},
			users: []identitymodel.IdentityUser{
				{ID: "admin", Status: identitymodel.IdentityStatusActive},
				{ID: "report-b", Status: identitymodel.IdentityStatusActive},
				{ID: "report-a", Status: identitymodel.IdentityStatusActive},
				{ID: "outside", Status: identitymodel.IdentityStatusActive},
			},
			assignments: []identitymodel.IdentityUserRoleAssignment{
				{UserID: "admin", RoleID: "role-one"},
				{UserID: "admin", RoleID: "role-disabled"},
				{UserID: "admin", RoleID: "role-expired", ExpiresAt: &expired},
				{UserID: "admin", RoleID: "role-missing"},
			},
		},
		permissionAssignments: []identitymodel.IdentityRolePermissionAssignment{{RoleID: "role-one", PermissionKey: "a.permission"}},
		dataScopes:            []identitymodel.IdentityDataScopePolicy{{Resource: "order", Scope: identitymodel.IdentityDataScope("owned")}},
		fieldPermissions:      []identitymodel.IdentityFieldPermission{{Resource: "order", Field: "amount", Visible: true, Editable: true}},
		workforceEntries: []identitymodel.IdentityWorkforceDirectoryEntry{
			{WorkforceProfileID: "admin-workforce", IdentityUserID: "admin", OrganizationUnitID: "department", OrganizationPath: "/department"},
			{WorkforceProfileID: "report-b-workforce", IdentityUserID: "report-b", ManagerIdentityUserID: "admin"},
			{WorkforceProfileID: "report-a-workforce", IdentityUserID: "report-a", ManagerIdentityUserID: "admin"},
			{WorkforceProfileID: "outside-workforce", IdentityUserID: "outside"},
		},
	}
	service := principalRoleService(t, repository)
	activateIdentityTestPermissions(service, "a.permission", "z.permission")
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "role-one", Name: "role-one", Permissions: []string{"a.permission", "z.permission"}, RecordScope: "all_records",
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true, Write: true}, {ObjectKey: "order", Scope: "owned", Read: true, Write: true}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "name", Read: true, Write: true}, {ObjectKey: "order", FieldKey: "amount", Read: true, Write: true}},
	}, {Key: "role-unassigned", Name: "role-unassigned", RecordScope: "all_records"}})
	principal, err := service.BuildPrincipal(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.UserID != "admin" || principal.Role.Key != "role-one" || principal.Role.Name != "role-one" {
		t.Fatalf("principal=%+v", principal)
	}
	if !reflect.DeepEqual(principal.Role.Permissions, []string{"a.permission", "z.permission"}) {
		t.Fatalf("permissions=%v", principal.Role.Permissions)
	}
	if !reflect.DeepEqual(principal.ReportingUserIDs, []string{"report-a", "report-b"}) || len(principal.Role.DataPermissions) != 2 || len(principal.Role.FieldPermissions) != 2 {
		t.Fatalf("principal=%+v", principal)
	}

	repository.assignments = append(repository.assignments, identitymodel.IdentityUserRoleAssignment{UserID: "admin", RoleID: "role-unassigned"})
	principal, err = service.BuildPrincipal(t.Context(), "admin")
	if err != nil || principal.Role.Key != "identity_effective" {
		t.Fatalf("multi-role principal=%+v err=%v", principal, err)
	}

	repository.workforceEntries = nil
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "admin", RoleID: "role-expired", ExpiresAt: &expired}}
	principal, err = service.BuildPrincipal(t.Context(), "admin")
	if err != nil || len(principal.ReportingUserIDs) != 0 || principal.Role.Key != "identity_effective" {
		t.Fatalf("empty-scope principal=%+v err=%v", principal, err)
	}
}

func TestBuildPrincipalUnknownIdentityEdges(t *testing.T) {
	repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{users: []identitymodel.IdentityUser{{ID: "disabled", Status: identitymodel.IdentityStatusDisabled}}}}
	service := principalRoleService(t, repository)
	for _, userID := range []string{"missing", "disabled"} {
		principal, err := service.BuildPrincipal(t.Context(), userID)
		if err != nil || principal.Known || principal.UserID != userID {
			t.Fatalf("user=%q principal=%+v err=%v", userID, principal, err)
		}
	}
}

func TestBuildPrincipalRepositoryFailureWindows(t *testing.T) {
	failure := errors.New("build principal repository failure")
	for _, test := range []struct {
		name      string
		configure func(*identityPrincipalRoleRepository)
	}{
		{name: "user", configure: func(r *identityPrincipalRoleRepository) { r.listUsersErr, r.listUsersFailAt = failure, 1 }},
		{name: "effective assignments", configure: func(r *identityPrincipalRoleRepository) { r.listAssignmentsErr, r.listAssignmentsFailAt = failure, 1 }},
		{name: "effective roles", configure: func(r *identityPrincipalRoleRepository) { r.listRolesErr, r.listRolesFailAt = failure, 1 }},
		{name: "workforce profiles", configure: func(r *identityPrincipalRoleRepository) { r.workforceProfilesErr = failure }},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{
				users:       []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
				roles:       []identitymodel.IdentityRole{{ID: "role", Key: "role", Status: identitymodel.IdentityStatusActive}},
				assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role"}},
			}}
			test.configure(repository)
			if _, err := principalRoleService(t, repository).BuildPrincipal(t.Context(), "user"); !errors.Is(err, failure) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestEffectivePermissionKeysUnknownIdentityEdges(t *testing.T) {
	repository := &identityPrincipalRoleRepository{identityRolesRepositoryStub: &identityRolesRepositoryStub{users: []identitymodel.IdentityUser{{ID: "disabled", Status: identitymodel.IdentityStatusDisabled}}}}
	service := principalRoleService(t, repository)
	for _, userID := range []string{"missing", "disabled"} {
		keys, err := service.EffectivePermissionKeys(t.Context(), userID)
		if err != nil || len(keys) != 0 {
			t.Fatalf("user=%q keys=%v err=%v", userID, keys, err)
		}
	}
	repository.listUsersErr, repository.listUsersFailAt, repository.listUsersCalls = errIdentityDepartmentUserEdge, 1, 0
	if _, err := service.EffectivePermissionKeys(t.Context(), "disabled"); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("effective permission lookup error=%v", err)
	}
}

func TestPublishedRoleDefinitionIsRuntimeAuthorizationAuthority(t *testing.T) {
	repository := &identityPrincipalRoleRepository{
		identityRolesRepositoryStub: &identityRolesRepositoryStub{
			users:       []identitymodel.IdentityUser{{ID: "user", Status: identitymodel.IdentityStatusActive}},
			roles:       []identitymodel.IdentityRole{{ID: "operator", Key: "operator", Label: "Operator directory entry", Status: identitymodel.IdentityStatusActive}},
			assignments: []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "operator"}},
		},
		permissionAssignments: []identitymodel.IdentityRolePermissionAssignment{{RoleID: "operator", PermissionKey: "stale.assignment.permission"}},
		dataScopes:            []identitymodel.IdentityDataScopePolicy{{Resource: "stale", Scope: identitymodel.IdentityDataScope("all_records")}},
		fieldPermissions:      []identitymodel.IdentityFieldPermission{{Resource: "stale", Field: "secret", Visible: true, Editable: true}},
	}
	service := principalRoleService(t, repository)
	activateIdentityTestPermissions(service, "order.complete", "order.read")
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "operator", Name: "Published operator", Permissions: []string{"order.complete"}, RecordScope: "all_records",
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "order", Scope: "owned", Read: true, Write: true}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "order", FieldKey: "status", Read: true, Write: true}},
	}})

	principal, err := service.BuildPrincipal(t.Context(), "user")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(principal.Role.Permissions, []string{"order.complete"}) || principal.Role.Name != "Published operator" || len(principal.Role.DataPermissions) != 1 || principal.Role.DataPermissions[0].ObjectKey != "order" || len(principal.Role.FieldPermissions) != 1 || principal.Role.FieldPermissions[0].FieldKey != "status" {
		t.Fatalf("published role did not own principal authorization: %#v", principal.Role)
	}
	keys, err := service.EffectivePermissionKeys(t.Context(), "user")
	if err != nil || !reflect.DeepEqual(keys, []string{"order.complete"}) {
		t.Fatalf("effective permissions=%v err=%v", keys, err)
	}
	selected, err := service.BuildPrincipalForRole(t.Context(), "user", "operator")
	if err != nil || !reflect.DeepEqual(selected.Role.Permissions, []string{"order.complete"}) {
		t.Fatalf("selected principal=%#v err=%v", selected, err)
	}

	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "operator", Name: "Published operator", Permissions: []string{"order.read"}, RecordScope: "all_records"}})
	principal, err = service.BuildPrincipal(t.Context(), "user")
	if err != nil || !reflect.DeepEqual(principal.Role.Permissions, []string{"order.read"}) {
		t.Fatalf("replacement snapshot was not observed atomically: principal=%#v err=%v", principal, err)
	}
}
