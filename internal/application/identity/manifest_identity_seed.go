package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	manifestrepository "github.com/domainry/domainry-identity/internal/domain/manifest/repository"
)

type Seed struct {
	Roles             []identitymodel.IdentityRole
	OrganizationUnits []identitymodel.IdentityOrganizationUnit
	Users             []identitymodel.IdentityUser
	UserRoles         []identitymodel.IdentityUserRoleAssignment
	Menus             []identitymodel.IdentityMenu
	RoleMenus         []identitymodel.IdentityRoleMenuAssignment
}

func FromManifest(manifest manifestmodel.ManifestSchema) Seed {
	seed := generatedManifestIdentitySeed()
	if manifest.IdentityBootstrap != nil {
		seed.OrganizationUnits = manifestIdentityOrganizationUnits(manifest.IdentityBootstrap.OrganizationUnits)
		seed.Menus = append(seed.Menus, manifest.IdentityBootstrap.Menus...)
		seed.RoleMenus = append(seed.RoleMenus, manifest.IdentityBootstrap.RoleMenus...)
		for _, roleMenuSet := range manifest.IdentityBootstrap.RoleMenuSets {
			for _, menuID := range roleMenuSet.MenuIDs {
				seed.RoleMenus = append(seed.RoleMenus, identitymodel.IdentityRoleMenuAssignment{RoleID: strings.TrimSpace(roleMenuSet.RoleID), MenuID: strings.TrimSpace(menuID)})
			}
		}
	}
	roleIndexByID := map[string]int{}
	for index, role := range seed.Roles {
		roleIndexByID[role.ID] = index
	}
	for _, role := range manifest.Roles {
		roleID := strings.TrimSpace(role.Key)
		if roleID == "" {
			continue
		}
		identityRole := identitymodel.IdentityRole{
			ID:     roleID,
			Key:    roleID,
			Label:  identityValueOrDefault(role.Name, roleID),
			Status: identitymodel.IdentityStatusActive,
		}
		if index, exists := roleIndexByID[roleID]; exists {
			seed.Roles[index] = identityRole
		} else {
			roleIndexByID[roleID] = len(seed.Roles)
			seed.Roles = append(seed.Roles, identityRole)
			seed.Users = append(seed.Users, identitymodel.IdentityUser{
				ID:     roleID + "_user",
				Name:   identityValueOrDefault(role.Name, roleID),
				Email:  roleID + "@example.com",
				Status: identitymodel.IdentityStatusActive,
			})
			seed.UserRoles = append(seed.UserRoles, identitymodel.IdentityUserRoleAssignment{UserID: roleID + "_user", RoleID: roleID})
		}
	}
	userIndexByID := map[string]int{}
	for index, user := range seed.Users {
		userIndexByID[user.ID] = index
	}
	configuredUsers := append([]identitymodel.ManifestIdentityUserSchema(nil), manifest.Users...)
	if manifest.IdentityBootstrap != nil {
		configuredUsers = append(configuredUsers, manifest.IdentityBootstrap.Users...)
	}
	for _, configured := range configuredUsers {
		userID := strings.TrimSpace(configured.ID)
		if userID == "" {
			continue
		}
		user := identitymodel.IdentityUser{
			ID: userID, Name: identityValueOrDefault(configured.Name, userID),
			GivenName: strings.TrimSpace(configured.GivenName), MiddleName: strings.TrimSpace(configured.MiddleName),
			FamilyName: strings.TrimSpace(configured.FamilyName), NamePrefix: strings.TrimSpace(configured.NamePrefix),
			NameSuffix: strings.TrimSpace(configured.NameSuffix), NativeName: strings.TrimSpace(configured.NativeName),
			NameLocale:    strings.TrimSpace(configured.NameLocale),
			AccountType:   configured.AccountType,
			Locale:        strings.TrimSpace(configured.Locale),
			Timezone:      strings.TrimSpace(configured.Timezone),
			OrgID:         strings.TrimSpace(configured.OrgID),
			SupportOrgID:  strings.TrimSpace(configured.SupportOrgID),
			ManagerUserID: strings.TrimSpace(configured.ManagerUserID),
			WorkerNo:      strings.TrimSpace(configured.WorkerNo),
			WorkerType:    configured.WorkerType,
			WorkStatus:    configured.WorkStatus,
			StartDate:     strings.TrimSpace(configured.StartDate),
			EndDate:       strings.TrimSpace(configured.EndDate),
			Email:         identityValueOrDefault(configured.Email, userID+"@example.com"),
			Phone:         strings.TrimSpace(configured.Phone),
			Status:        identitymodel.IdentityStatus(identityValueOrDefault(configured.Status, string(identitymodel.IdentityStatusActive))),
		}
		if index, exists := userIndexByID[userID]; exists {
			seed.Users[index] = user
		} else {
			userIndexByID[userID] = len(seed.Users)
			seed.Users = append(seed.Users, user)
		}
		for _, roleKey := range configured.RoleKeys {
			if roleKey = strings.TrimSpace(roleKey); roleKey != "" {
				seed.UserRoles = append(seed.UserRoles, identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: roleKey})
			}
		}
	}
	if manifest.IdentityBootstrap != nil {
		for _, assignment := range manifest.IdentityBootstrap.UserRoleAssignments {
			seed.UserRoles = append(seed.UserRoles, identitymodel.IdentityUserRoleAssignment{
				UserID: strings.TrimSpace(assignment.UserID),
				RoleID: strings.TrimSpace(assignment.RoleID),
			})
		}
	}
	seed.Users = manifestIdentityUserReportingPaths(seed.Users)
	return seed
}

func manifestIdentityUserReportingPaths(users []identitymodel.IdentityUser) []identitymodel.IdentityUser {
	byID := make(map[string]identitymodel.IdentityUser, len(users))
	for _, user := range users {
		byID[user.ID] = user
	}
	resolved := make(map[string]string, len(users))
	visiting := map[string]bool{}
	var resolve func(string) string
	resolve = func(userID string) string {
		if path := resolved[userID]; path != "" {
			return path
		}
		user, found := byID[userID]
		if !found || visiting[userID] {
			return ""
		}
		visiting[userID] = true
		path := "/" + userID
		if managerID := strings.TrimSpace(user.ManagerUserID); managerID != "" {
			if managerPath := resolve(managerID); managerPath != "" {
				path = strings.TrimRight(managerPath, "/") + "/" + userID
			}
		}
		delete(visiting, userID)
		resolved[userID] = path
		return path
	}
	for index := range users {
		users[index].ReportingPath = resolve(users[index].ID)
	}
	return users
}

func manifestIdentityOrganizationUnits(configured []identitymodel.ManifestIdentityOrganizationUnitSchema) []identitymodel.IdentityOrganizationUnit {
	byID := map[string]identitymodel.ManifestIdentityOrganizationUnitSchema{}
	for _, organizationUnit := range configured {
		if id := strings.TrimSpace(organizationUnit.ID); id != "" {
			byID[id] = organizationUnit
		}
	}
	resolved := map[string]identitymodel.IdentityOrganizationUnit{}
	var resolve func(string) identitymodel.IdentityOrganizationUnit
	resolve = func(id string) identitymodel.IdentityOrganizationUnit {
		if organizationUnit, exists := resolved[id]; exists {
			return organizationUnit
		}
		configuredUnit := byID[id]
		organizationUnit := identitymodel.IdentityOrganizationUnit{
			ID:        id,
			Code:      identityValueOrDefault(strings.TrimSpace(configuredUnit.Code), id),
			Name:      strings.TrimSpace(configuredUnit.Name),
			NodeType:  configuredUnit.NodeType,
			ParentID:  configuredUnit.ParentID,
			Path:      "/" + id,
			SortOrder: configuredUnit.SortOrder,
			Status:    identitymodel.IdentityStatus(identityValueOrDefault(configuredUnit.Status, string(identitymodel.IdentityStatusActive))),
		}
		if organizationUnit.NodeType == "" {
			organizationUnit.NodeType = identitymodel.IdentityOrganizationUnitDepartment
		}
		if configuredUnit.ParentID != nil {
			parentID := strings.TrimSpace(*configuredUnit.ParentID)
			if _, exists := byID[parentID]; exists {
				parent := resolve(parentID)
				organizationUnit.Path = strings.TrimRight(parent.Path, "/") + "/" + id
				organizationUnit.AncestorIDs = append(append([]string(nil), parent.AncestorIDs...), parent.ID)
				organizationUnit.Depth = parent.Depth + 1
			}
		}
		resolved[id] = organizationUnit
		return organizationUnit
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]identitymodel.IdentityOrganizationUnit, 0, len(ids))
	for _, id := range ids {
		out = append(out, resolve(id))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		if out[i].SortOrder != out[j].SortOrder {
			return out[i].SortOrder < out[j].SortOrder
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func manifestMenuSortOrder(value int, index int) int {
	if value > 0 {
		return value
	}
	return (index + 1) * 10
}

func SyncIdentitySeeds(ctx context.Context, checkpoint manifestrepository.IdentitySeedCheckpointRepository, identityStore identityrepository.IdentitySeedRepository, manifest manifestmodel.ManifestSchema, seed Seed, scope identitymodel.SystemScope) error {
	if _, err := identitymodel.NewSystemCommandScope(scope); err != nil {
		return err
	}
	if checkpoint == nil || identityStore == nil || strings.TrimSpace(manifest.Version) == "" {
		return nil
	}
	syncedVersion, err := checkpoint.ManifestIdentitySeedSyncedVersion(ctx)
	if err != nil {
		return err
	}
	seedSignature := seedSyncSignature(manifest, seed)
	if syncedVersion == seedSignature {
		workspaceID := manifestIdentityWorkspaceID(ctx)
		roles, listErr := identityStore.ListIdentityRoles(ctx, workspaceID)
		if listErr != nil {
			return listErr
		}
		if len(roles) != 0 {
			return nil
		}
	}
	if err := syncManifestIdentityRoles(ctx, identityStore, seed.Roles); err != nil {
		return err
	}
	if err := identityStore.ApplyIdentityBootstrapAtomically(ctx, manifestIdentityWorkspaceID(ctx), seed.OrganizationUnits, seed.Users, seed.UserRoles); err != nil {
		return fmt.Errorf("sync manifest Identity Bootstrap atomically: %w", err)
	}
	declaredUserIDs := map[string]bool{}
	for _, user := range manifest.Users {
		declaredUserIDs[strings.TrimSpace(user.ID)] = true
	}
	if manifest.IdentityBootstrap != nil {
		for _, user := range manifest.IdentityBootstrap.Users {
			declaredUserIDs[strings.TrimSpace(user.ID)] = true
		}
	}
	for _, user := range seed.Users {
		if !declaredUserIDs[user.ID] {
			continue
		}
		if err := identityStore.UpsertIdentityUser(ctx, manifestIdentityWorkspaceID(ctx), user); err != nil {
			return fmt.Errorf("sync declared identity user %s: %w", user.ID, err)
		}
	}
	if err := syncManifestIdentityMenus(ctx, identityStore, seed.Menus); err != nil {
		return err
	}
	if err := syncManifestIdentityRoleMenus(ctx, identityStore, seed.Roles, seed.RoleMenus); err != nil {
		return err
	}
	if err := syncManifestIdentityMenuRetirements(ctx, identityStore, seed.Menus); err != nil {
		return err
	}
	if err := retireRemovedPlatformIdentityMenus(ctx, identityStore); err != nil {
		return err
	}
	return checkpoint.SetManifestIdentitySeedSyncedVersion(ctx, seedSignature)
}

func manifestIdentityWorkspaceID(ctx context.Context) string {
	return requestcontext.WorkspaceID(ctx)
}

func retireRemovedPlatformIdentityMenus(ctx context.Context, identityStore identityrepository.IdentitySeedRepository) error {
	retiredKeys := map[string]bool{
		"org_permissions":             true,
		"identity_permission_list":    true,
		"runtime_operations":          true,
		"system_overview":             true,
		"system_dictionaries":         true,
		"system_workflows":            true,
		"system_actions":              true,
		"system_automation_rules":     true,
		"system_connectors":           true,
		"system_notifications":        true,
		"system_scheduler":            true,
		"system_domain_impact":        true,
		"system_workflow_processes":   true,
		"system_operations":           true,
		"system_connector_operations": true,
		"system_scheduler_operations": true,
		"system_capability_status":    true,
	}
	workspaceID := manifestIdentityWorkspaceID(ctx)
	menus, err := identityStore.ListIdentityMenus(ctx, workspaceID)
	if err != nil {
		return err
	}
	byParent := map[string][]identitymodel.IdentityMenu{}
	retiredIDs := map[string]bool{}
	for _, menu := range menus {
		byParent[menu.ParentID] = append(byParent[menu.ParentID], menu)
		if retiredKeys[menu.Key] {
			retiredIDs[menu.ID] = true
		}
	}
	removed := map[string]bool{}
	var removeTree func(string) error
	removeTree = func(parentID string) error {
		if removed[parentID] {
			return nil
		}
		for _, child := range byParent[parentID] {
			if err := removeTree(child.ID); err != nil {
				return err
			}
		}
		if err := identityStore.RemoveIdentityMenu(ctx, workspaceID, parentID); err != nil {
			return fmt.Errorf("retire removed platform menu %s: %w", parentID, err)
		}
		removed[parentID] = true
		return nil
	}
	for menuID := range retiredIDs {
		if err := removeTree(menuID); err != nil {
			return err
		}
	}
	return nil
}

func seedSyncSignature(manifest manifestmodel.ManifestSchema, seed Seed) string {
	raw, _ := json.Marshal(struct {
		SyncSchema        string                                     `json:"sync_schema"`
		Version           string                                     `json:"version"`
		Roles             []identitymodel.IdentityRole               `json:"roles"`
		OrganizationUnits []identitymodel.IdentityOrganizationUnit   `json:"organization_units"`
		Users             []identitymodel.IdentityUser               `json:"users"`
		UserRoles         []identitymodel.IdentityUserRoleAssignment `json:"user_roles"`
		Menus             []identitymodel.IdentityMenu               `json:"menus"`
		RoleMenus         []identitymodel.IdentityRoleMenuAssignment `json:"role_menus"`
	}{
		SyncSchema:        "identity_seed_sync.v1",
		Version:           strings.TrimSpace(manifest.Version),
		Roles:             seed.Roles,
		OrganizationUnits: seed.OrganizationUnits,
		Users:             seed.Users,
		UserRoles:         seed.UserRoles,
		Menus:             seed.Menus,
		RoleMenus:         seed.RoleMenus,
	})
	sum := sha256.Sum256(raw)
	return strings.TrimSpace(manifest.Version) + ":" + hex.EncodeToString(sum[:])
}
