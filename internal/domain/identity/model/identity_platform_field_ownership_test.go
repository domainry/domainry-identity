package identitymodel

import (
	"reflect"
	"testing"
)

func TestIdentityPlatformOwnerForProfileFieldSeparatesAccountAndWorkforce(t *testing.T) {
	for _, field := range []string{"account_status", "password"} {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerAccount {
			t.Errorf("account field %q owner=%q owned=%v", field, owner, owned)
		}
	}
	for _, field := range []string{"employee_no", "hire_date", "job_title", "job_level", "employment_type", "employment_status", "department_id", "department_path", "manager_id", "manager_path", "manager_ancestor_ids", "manager_depth", "reporting_path"} {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerWorkforce {
			t.Errorf("workforce field %q owner=%q owned=%v", field, owner, owned)
		}
	}
	for _, field := range []string{"email", "phone", "gender", "member_status", "student_no"} {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); owned || owner != "" {
			t.Errorf("business field %q owner=%q owned=%v", field, owner, owned)
		}
	}
}

func TestIdentityAccountModelsExposeOnlyAccountFacts(t *testing.T) {
	for name, value := range map[string]any{
		"IdentityUser":               IdentityUser{},
		"ManifestIdentityUserSchema": ManifestIdentityUserSchema{},
	} {
		typeOf := reflect.TypeOf(value)
		fields := map[string]bool{}
		for index := 0; index < typeOf.NumField(); index++ {
			fields[typeOf.Field(index).Name] = true
		}
		for _, allowed := range []string{
			"ID",
			"Name",
			"GivenName",
			"MiddleName",
			"FamilyName",
			"NamePrefix",
			"NameSuffix",
			"NativeName",
			"NameLocale",
			"Email",
			"Phone",
			"AccountType",
			"Locale",
			"Timezone",
			"Status",
			"Version",
			"CreatedAt",
			"UpdatedAt",
		} {
			delete(fields, allowed)
		}
		if name == "ManifestIdentityUserSchema" {
			delete(fields, "RoleKeys")
		}
		if len(fields) != 0 {
			t.Fatalf("%s retains non-account facts: %#v", name, fields)
		}
	}
}
