package identitymodel

type IdentityPlatformFieldOwner string

const (
	IdentityPlatformFieldOwnerAccount IdentityPlatformFieldOwner = "identity_account"
	IdentityPlatformFieldOwnerUser    IdentityPlatformFieldOwner = "identity_user"
)

var identityAccountOwnedProfileFields = map[string]struct{}{
	"account_status": {},
	"password":       {},
}

var identityUserOwnedProfileFields = map[string]struct{}{
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

// IdentityPlatformOwnerForProfileField reports the platform entity that owns a
// reserved profile field. An empty owner means the business Profile may own the
// field. Contact email/phone and gender may be valid business-Profile facts;
// gender remains business-owned until an optional Person Foundation contract
// is introduced.
func IdentityPlatformOwnerForProfileField(fieldKey string) (IdentityPlatformFieldOwner, bool) {
	if _, owned := identityAccountOwnedProfileFields[fieldKey]; owned {
		return IdentityPlatformFieldOwnerAccount, true
	}
	if _, owned := identityUserOwnedProfileFields[fieldKey]; owned {
		return IdentityPlatformFieldOwnerUser, true
	}
	return "", false
}
