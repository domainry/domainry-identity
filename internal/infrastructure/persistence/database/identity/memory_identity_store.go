// In-memory identity persistence.
package identity

import (
	"strings"
	"sync"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityWorkspacePrefix(workspaceID string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return "", err
	}
	return workspace.String() + "\x00", nil
}

func identityWorkspaceKey(workspaceID string, values ...string) (string, error) {
	prefix, err := identityWorkspacePrefix(workspaceID)
	if err != nil {
		return "", err
	}
	return prefix + strings.Join(values, "\x00"), nil
}

type MemoryIdentityStore struct {
	mu                   sync.RWMutex
	departments          map[string]identitymodel.IdentityDepartment
	users                map[string]identitymodel.IdentityUser
	workforceProfiles    map[string]identitymodel.IdentityWorkforceProfile
	workforceAssignments map[string]identitymodel.IdentityWorkforceAssignment
	roles                map[string]identitymodel.IdentityRole
	userRoles            map[string]identitymodel.IdentityUserRoleAssignment
	entitlementReceipts  map[string]identitymodel.IdentityEntitlementBatchReceipt
	roleRequests         map[string]identitymodel.IdentityRoleRequest
	menus                map[string]identitymodel.IdentityMenu
	roleMenus            map[string][]string
	credentials          map[string]identitymodel.IdentityCredential
	refreshTokens        map[string]identitymodel.AuthRefreshToken
	externalAccounts     map[string]identitymodel.IdentityExternalAccount
}

func NewMemoryIdentityStore() *MemoryIdentityStore {
	return &MemoryIdentityStore{
		departments:          map[string]identitymodel.IdentityDepartment{},
		users:                map[string]identitymodel.IdentityUser{},
		workforceProfiles:    map[string]identitymodel.IdentityWorkforceProfile{},
		workforceAssignments: map[string]identitymodel.IdentityWorkforceAssignment{},
		roles:                map[string]identitymodel.IdentityRole{},
		userRoles:            map[string]identitymodel.IdentityUserRoleAssignment{},
		entitlementReceipts:  map[string]identitymodel.IdentityEntitlementBatchReceipt{},
		roleRequests:         map[string]identitymodel.IdentityRoleRequest{},
		menus:                map[string]identitymodel.IdentityMenu{},
		roleMenus:            map[string][]string{},
		credentials:          map[string]identitymodel.IdentityCredential{},
		refreshTokens:        map[string]identitymodel.AuthRefreshToken{},
		externalAccounts:     map[string]identitymodel.IdentityExternalAccount{},
	}
}
