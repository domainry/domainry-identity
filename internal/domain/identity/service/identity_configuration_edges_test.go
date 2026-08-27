package service

import (
	"errors"
	"testing"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityIssueCodes(issues []identitycontract.IdentityGovernanceValidationIssue) map[string]bool {
	codes := make(map[string]bool, len(issues))
	for _, issue := range issues {
		codes[issue.ErrorCode] = true
	}
	return codes
}

func requireIdentityIssue(t *testing.T, issues []identitycontract.IdentityGovernanceValidationIssue, code string) {
	t.Helper()
	if !identityIssueCodes(issues)[code] {
		t.Fatalf("missing issue %q in %+v", code, issues)
	}
}

func TestValidateUserConfigurationContractMatrix(t *testing.T) {
	repository := &identityDepartmentUserRepository{}
	service := NewIdentityConfigurationDomainService(repository).ForWorkspace("workspace")

	invalid, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
		ID: " unsafe/id ", Email: "bad", Status: "invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{
		"backend.identity.user_path_unsafe",
		"backend.identity.user_name_required",
		"backend.identity.user_email_invalid",
		"backend.identity.user_status_invalid",
	} {
		requireIdentityIssue(t, invalid, code)
	}

	missing, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"backend.identity.user_required", "backend.identity.user_name_required", "backend.identity.user_email_required"} {
		requireIdentityIssue(t, missing, code)
	}

	for _, status := range []identitymodel.IdentityStatus{"", identitymodel.IdentityStatusActive, identitymodel.IdentityStatusDisabled} {
		valid, validationErr := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
			ID: "user", Name: "User", Email: "user@example.com", Status: status,
		})
		if validationErr != nil || len(valid) != 0 {
			t.Fatalf("status=%q issues=%+v err=%v", status, valid, validationErr)
		}
	}

	formatted, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{ID: "user", Name: "User", Email: "Name <user@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	requireIdentityIssue(t, formatted, "backend.identity.user_email_invalid")

	for _, accountType := range []identitymodel.IdentityAccountType{
		identitymodel.IdentityAccountHuman,
		identitymodel.IdentityAccountService,
		identitymodel.IdentityAccountAutomation,
	} {
		got, validationErr := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
			ID: "user", Name: "User", Email: "user@example.com", AccountType: accountType,
		})
		if validationErr != nil || len(got) != 0 {
			t.Fatalf("accountType=%q issues=%+v err=%v", accountType, got, validationErr)
		}
	}
	invalidAccount, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
		ID: "user", Name: "User", Email: "user@example.com", AccountType: identitymodel.IdentityAccountType("invalid"),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireIdentityIssue(t, invalidAccount, "backend.identity.user_account_type_invalid")

	invalidTimezone, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
		ID: "user", Name: "User", Email: "user@example.com", Timezone: "Not/A_Timezone",
	})
	if err != nil {
		t.Fatal(err)
	}
	requireIdentityIssue(t, invalidTimezone, "backend.identity.user_timezone_invalid")
	validTimezone, err := service.ValidateUserConfiguration(t.Context(), identitymodel.IdentityUser{
		ID: "user", Name: "User", Email: "user@example.com", Timezone: "Asia/Shanghai",
	})
	if err != nil || len(validTimezone) != 0 {
		t.Fatalf("valid timezone issues=%+v err=%v", validTimezone, err)
	}
}

func TestValidateUserConfigurationReferencesAndFailures(t *testing.T) {
	user := identitymodel.IdentityUser{ID: "user", Name: "User", Email: "user@example.com"}
	repository := &identityDepartmentUserRepository{users: []identitymodel.IdentityUser{
		{ID: "user", Email: "user@example.com"},
		{ID: "other", Email: "USER@example.com"},
	}}
	service := NewIdentityConfigurationDomainService(repository)

	issues, err := service.ValidateUserConfiguration(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	requireIdentityIssue(t, issues, "backend.identity.user_email_exists")

	repository.listUserErr = errIdentityDepartmentUserEdge
	if _, err := service.ValidateUserConfiguration(t.Context(), user); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("list users error=%v", err)
	}
}

func TestIdentityConfigurationHelperEdges(t *testing.T) {
	other := identitymodel.IdentityUser{ID: "other", Email: "other@example.com"}
	if issues := validateUserUniqueness(identitymodel.IdentityUser{ID: "user"}, []identitymodel.IdentityUser{other}); len(issues) != 0 {
		t.Fatalf("blank optional identity values produced issues: %+v", issues)
	}
}

func TestIdentityConfigurationAssignmentExpiryAndErrorHelpers(t *testing.T) {
	repository := &identityRolesRepositoryStub{
		users: []identitymodel.IdentityUser{{ID: "user"}},
		roles: []identitymodel.IdentityRole{{ID: "role"}},
	}
	service := NewIdentityConfigurationDomainService(repository)
	blank := " "
	for _, expiresAt := range []*string{nil, &blank} {
		issues, err := service.ValidateRoleAssignmentConfiguration(t.Context(), identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role", ExpiresAt: expiresAt})
		if err != nil || len(issues) != 0 {
			t.Fatalf("expiresAt=%v issues=%+v err=%v", expiresAt, issues, err)
		}
	}
	for _, test := range []struct {
		name       string
		assignment identitymodel.IdentityUserRoleAssignment
		code       string
	}{
		{name: "valid times and enums", assignment: identitymodel.IdentityUserRoleAssignment{
			UserID: "user", RoleID: "role", ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
			RevokedAt: "2026-06-01T00:00:00Z", Source: "manual", Status: "active",
		}},
		{name: "invalid time", assignment: identitymodel.IdentityUserRoleAssignment{
			UserID: "user", RoleID: "role", ValidFrom: "not-a-time",
		}, code: "backend.identity.assignment_time_invalid"},
		{name: "invalid source", assignment: identitymodel.IdentityUserRoleAssignment{
			UserID: "user", RoleID: "role", Source: "unknown",
		}, code: "backend.identity.assignment_source_invalid"},
		{name: "invalid status", assignment: identitymodel.IdentityUserRoleAssignment{
			UserID: "user", RoleID: "role", Status: "unknown",
		}, code: "backend.identity.assignment_status_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			issues, err := service.ValidateRoleAssignmentConfiguration(t.Context(), test.assignment)
			if err != nil {
				t.Fatal(err)
			}
			if test.code == "" {
				if len(issues) != 0 {
					t.Fatalf("issues=%+v", issues)
				}
				return
			}
			requireIdentityIssue(t, issues, test.code)
		})
	}
	cause := errors.New("storage")
	if err := internalError("load identity", cause); !errors.Is(err, cause) {
		t.Fatalf("internal error lost cause: %v", err)
	}
	if err := badRequest("code", "", "ignored"); err == nil {
		t.Fatal("identity error with blank parameter key was nil")
	}
}

func TestValidateDepartmentConfigurationContractAndHierarchyMatrix(t *testing.T) {
	repository := &identityDepartmentUserRepository{}
	service := NewIdentityConfigurationDomainService(repository)

	issues, err := service.ValidateDepartmentConfiguration(t.Context(), identitymodel.IdentityDepartment{Status: "invalid"})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"backend.identity.department_id_required", "backend.identity.department_name_required", "backend.identity.department_status_invalid"} {
		requireIdentityIssue(t, issues, code)
	}
	for _, status := range []identitymodel.IdentityStatus{"", identitymodel.IdentityStatusActive, identitymodel.IdentityStatusDisabled} {
		got, validateErr := service.ValidateDepartmentConfiguration(t.Context(), identitymodel.IdentityDepartment{ID: "department", Name: "Department", Status: status})
		if validateErr != nil || len(got) != 0 {
			t.Fatalf("status=%q issues=%+v err=%v", status, got, validateErr)
		}
	}

	blank := " "
	parent := "parent"
	missing := "missing"
	self := "department"
	cycle := "department"
	broken := "broken"
	for _, test := range []struct {
		name        string
		parentID    *string
		departments []identitymodel.IdentityDepartment
		wantCode    string
	}{
		{name: "nil"},
		{name: "blank", parentID: &blank},
		{name: "self", parentID: &self, wantCode: "backend.identity.department_parent_self"},
		{name: "missing", parentID: &missing, wantCode: "backend.identity.parent_department_not_found"},
		{name: "valid", parentID: &parent, departments: []identitymodel.IdentityDepartment{{ID: "parent"}}},
		{name: "cycle", parentID: &parent, departments: []identitymodel.IdentityDepartment{{ID: "parent", ParentID: &cycle}, {ID: "department"}}, wantCode: "backend.identity.department_cycle"},
		{name: "broken", parentID: &parent, departments: []identitymodel.IdentityDepartment{{ID: "parent", ParentID: &broken}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository.departments = test.departments
			got, validateErr := service.ValidateDepartmentConfiguration(t.Context(), identitymodel.IdentityDepartment{ID: "department", Name: "Department", ParentID: test.parentID})
			if validateErr != nil {
				t.Fatal(validateErr)
			}
			if test.wantCode == "" {
				if len(got) != 0 {
					t.Fatalf("issues=%+v", got)
				}
			} else {
				requireIdentityIssue(t, got, test.wantCode)
			}
		})
	}

	root := "root"
	repository.departments = []identitymodel.IdentityDepartment{
		{ID: "same", Name: "Department", ParentID: &root},
		{ID: "other", Name: " department ", ParentID: &root},
		{ID: "different-parent", Name: "Department"},
		{ID: "different-name", Name: "Other", ParentID: &root},
	}
	issues, err = service.ValidateDepartmentConfiguration(t.Context(), identitymodel.IdentityDepartment{ID: "same", Name: "Department", ParentID: &root})
	if err != nil {
		t.Fatal(err)
	}
	requireIdentityIssue(t, issues, "backend.identity.department_name_exists")

	repository.listDepartmentErr = errIdentityDepartmentUserEdge
	if _, err := service.ValidateDepartmentConfiguration(t.Context(), identitymodel.IdentityDepartment{ID: "id", Name: "Name"}); !errors.Is(err, errIdentityDepartmentUserEdge) {
		t.Fatalf("list departments error=%v", err)
	}
}
