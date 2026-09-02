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
	documentedUserFields := map[string]struct{}{
		"org_id":            {},
		"support_org_id":    {},
		"organization_path": {},
		"manager_user_id":   {},
		"reporting_path":    {},
		"worker_no":         {},
		"worker_type":       {},
		"work_status":       {},
		"start_date":        {},
		"end_date":          {},
	}
	assertFieldSetEqual(t, "identity_account", identityAccountOwnedProfileFields, documentedAccountFields)
	assertFieldSetEqual(t, "identity_user", identityUserOwnedProfileFields, documentedUserFields)
	for field := range documentedAccountFields {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerAccount {
			t.Fatalf("field %q must resolve to identity_account owner, got %q owned=%v", field, owner, owned)
		}
	}
	for field := range documentedUserFields {
		if owner, owned := IdentityPlatformOwnerForProfileField(field); !owned || owner != IdentityPlatformFieldOwnerUser {
			t.Fatalf("field %q must resolve to identity_user owner, got %q owned=%v", field, owner, owned)
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
