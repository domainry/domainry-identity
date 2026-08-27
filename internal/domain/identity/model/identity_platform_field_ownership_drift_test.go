package identitymodel

import "testing"

// Pins the platform field-ownership maps to the reserved-field table published
// in skills/domainry-builder-v1/references/capabilities/
// identity-account-and-profile.md. If either side changes, this test forces
// the doc and the code to move together.

func TestIdentityPlatformFieldOwnershipMatchesCapabilityDoc(t *testing.T) {
	documentedAccountFields := map[string]struct{}{
		"account_status": {},
		"password":       {},
	}
	documentedWorkforceFields := map[string]struct{}{
		"department_id":        {},
		"department_path":      {},
		"employee_no":          {},
		"employment_status":    {},
		"employment_type":      {},
		"hire_date":            {},
		"job_level":            {},
		"job_title":            {},
		"manager_ancestor_ids": {},
		"manager_depth":        {},
		"manager_id":           {},
		"manager_path":         {},
		"reporting_path":       {},
	}
	assertFieldSetEqual(t, "identity_account", identityAccountOwnedProfileFields, documentedAccountFields)
	assertFieldSetEqual(t, "workforce", identityWorkforceOwnedProfileFields, documentedWorkforceFields)
	for field := range documentedAccountFields {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerAccount {
			t.Fatalf("field %q must resolve to identity_account owner, got %q owned=%v", field, owner, owned)
		}
	}
	for field := range documentedWorkforceFields {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerWorkforce {
			t.Fatalf("field %q must resolve to workforce owner, got %q owned=%v", field, owner, owned)
		}
	}
	// The doc explicitly keeps contact and person facts business-ownable.
	for _, field := range []string{"email", "phone", "gender"} {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); owned {
			t.Fatalf("doc claims %q stays business-ownable, but platform owner %q claims it", field, owner)
		}
	}
}

func assertFieldSetEqual(t *testing.T, owner string, actual map[string]struct{}, documented map[string]struct{}) {
	t.Helper()
	for field := range actual {
		if _, ok := documented[field]; !ok {
			t.Fatalf("platform map for %s owns %q but the capability doc table does not list it", owner, field)
		}
	}
	for field := range documented {
		if _, ok := actual[field]; !ok {
			t.Fatalf("capability doc lists %q under %s but the platform map does not own it", field, owner)
		}
	}
}
