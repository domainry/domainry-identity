package identitymodel

type IdentityPlatformFieldOwner string

const (
	IdentityPlatformFieldOwnerAccount   IdentityPlatformFieldOwner = "identity_account"
	IdentityPlatformFieldOwnerWorkforce IdentityPlatformFieldOwner = "workforce"
)

var identityAccountOwnedProfileFields = map[string]struct{}{
	"account_status": {},
	"password":       {},
}

var identityWorkforceOwnedProfileFields = map[string]struct{}{
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

// IdentityPlatformOwnerForProfileField reports the platform entity that owns a
// reserved profile field. An empty owner means the business Profile may own the
// field. Contact email/phone and gender may be valid business-Profile facts;
// gender remains business-owned until an optional Person Foundation contract
// is introduced.
func IdentityPlatformOwnerForProfileField(fieldKey string) (IdentityPlatformFieldOwner, bool) {
	if _, owned := identityAccountOwnedProfileFields[fieldKey]; owned {
		return IdentityPlatformFieldOwnerAccount, true
	}
	if _, owned := identityWorkforceOwnedProfileFields[fieldKey]; owned {
		return IdentityPlatformFieldOwnerWorkforce, true
	}
	return "", false
}
