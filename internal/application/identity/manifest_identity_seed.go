package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/entityid"
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

type identitySeedUserReader interface {
	GetIdentityUser(context.Context, string, string) (identitymodel.IdentityUser, bool, error)
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
		roleIndexByID[role.RoleID] = index
	}
	for _, role := range manifest.Roles {
		roleID := strings.TrimSpace(role.Key)
		if roleID == "" {
			continue
		}
		identityRole := identitymodel.IdentityRole{
			RoleID: roleID,
			Key:    roleID,
			Label:  identityValueOrDefault(role.Name, roleID),
			Status: identitymodel.IdentityStatusActive,
		}
		if index, exists := roleIndexByID[roleID]; exists {
			seed.Roles[index] = identityRole
		} else {
			roleIndexByID[roleID] = len(seed.Roles)
			seed.Roles = append(seed.Roles, identityRole)
		}
		seed = ensureManifestRoleBootstrapUser(seed, roleID, identityValueOrDefault(role.Name, roleID))
	}
	userIndexByID := map[string]int{}
	for index, user := range seed.Users {
		userIndexByID[user.UserID] = index
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
			UserID: userID, Name: identityValueOrDefault(configured.Name, userID),
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

func ensureManifestRoleBootstrapUser(seed Seed, roleID, roleName string) Seed {
	for _, assignment := range seed.UserRoles {
		if strings.TrimSpace(assignment.RoleID) == roleID {
			return seed
		}
	}
	userID := roleID + "_user"
	seed.Users = append(seed.Users, identitymodel.IdentityUser{
		UserID: userID,
		Name:   roleName,
		Email:  roleID + "@example.com",
		Status: identitymodel.IdentityStatusActive,
	})
	seed.UserRoles = append(seed.UserRoles, identitymodel.IdentityUserRoleAssignment{UserID: userID, RoleID: roleID})
	return seed
}

func manifestIdentityUserReportingPaths(users []identitymodel.IdentityUser) []identitymodel.IdentityUser {
	byID := make(map[string]identitymodel.IdentityUser, len(users))
	for _, user := range users {
		byID[user.UserID] = user
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
		users[index].ReportingPath = resolve(users[index].UserID)
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
			OrganizationUnitID: id,
			Code:               identityValueOrDefault(strings.TrimSpace(configuredUnit.Code), id),
			Name:               strings.TrimSpace(configuredUnit.Name),
			NodeType:           configuredUnit.NodeType,
			ParentID:           configuredUnit.ParentID,
			Path:               "/" + id,
			SortOrder:          configuredUnit.SortOrder,
			Status:             identitymodel.IdentityStatus(identityValueOrDefault(configuredUnit.Status, string(identitymodel.IdentityStatusActive))),
		}
		if organizationUnit.NodeType == "" {
			organizationUnit.NodeType = identitymodel.IdentityOrganizationUnitDepartment
		}
		if configuredUnit.ParentID != nil {
			parentID := strings.TrimSpace(*configuredUnit.ParentID)
			if _, exists := byID[parentID]; exists {
				parent := resolve(parentID)
				organizationUnit.Path = strings.TrimRight(parent.Path, "/") + "/" + id
				organizationUnit.AncestorIDs = append(append([]string(nil), parent.AncestorIDs...), parent.OrganizationUnitID)
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
		return out[i].OrganizationUnitID < out[j].OrganizationUnitID
	})
	return out
}

func manifestMenuSortOrder(value int, index int) int {
	if value > 0 {
		return value
	}
	return (index + 1) * 10
}

func SyncIdentitySeeds(ctx context.Context, checkpoint manifestrepository.IdentitySeedCheckpointRepository, identityStore identityrepository.IdentitySeedRepository, manifest manifestmodel.ManifestSchema, seed Seed, scope identitymodel.SystemScope) (Seed, error) {
	if _, err := identitymodel.NewSystemCommandScope(scope); err != nil {
		return Seed{}, err
	}
	if checkpoint == nil || identityStore == nil || strings.TrimSpace(manifest.Version) == "" {
		return seed, nil
	}
	syncedVersion, err := checkpoint.ManifestIdentitySeedSyncedVersion(ctx)
	if err != nil {
		return Seed{}, err
	}
	workspaceID := manifestIdentityWorkspaceID(ctx)
	seed, err = materializeIdentitySeed(workspaceID, seed)
	if err != nil {
		return Seed{}, err
	}
	seed, err = scopeGeneratedSeedLoginNames(ctx, identityStore, manifest, seed, workspaceID)
	if err != nil {
		return Seed{}, err
	}
	seedSignature := seedSyncSignature(manifest, seed)
	if syncedVersion == seedSignature {
		roles, listErr := identityStore.ListIdentityRoles(ctx, workspaceID)
		if listErr != nil {
			return Seed{}, listErr
		}
		if len(roles) != 0 {
			return seed, nil
		}
	}
	if err := syncManifestIdentityRoles(ctx, identityStore, seed.Roles); err != nil {
		return Seed{}, err
	}
	seed, err = preserveExistingImplicitSeedUsers(ctx, identityStore, manifest, seed)
	if err != nil {
		return Seed{}, err
	}
	if err := identityStore.ApplyIdentityBootstrapAtomically(ctx, manifestIdentityWorkspaceID(ctx), seed.OrganizationUnits, seed.Users, seed.UserRoles); err != nil {
		return Seed{}, fmt.Errorf("sync manifest Identity Bootstrap atomically: %w", err)
	}
	declaredUserIDs := manifestDeclaredIdentityUserIDs(workspaceID, manifest)
	for _, user := range seed.Users {
		if !declaredUserIDs[user.UserID] {
			continue
		}
		if err := identityStore.UpsertIdentityUser(ctx, manifestIdentityWorkspaceID(ctx), user); err != nil {
			return Seed{}, fmt.Errorf("sync declared identity user %s: %w", user.UserID, err)
		}
	}
	if err := syncManifestIdentityMenus(ctx, identityStore, seed.Menus); err != nil {
		return Seed{}, err
	}
	if err := syncManifestIdentityRoleMenus(ctx, identityStore, seed.Roles, seed.RoleMenus); err != nil {
		return Seed{}, err
	}
	if err := syncManifestIdentityMenuRetirements(ctx, identityStore, seed.Menus); err != nil {
		return Seed{}, err
	}
	if err := retireRemovedPlatformIdentityMenus(ctx, identityStore); err != nil {
		return Seed{}, err
	}
	if err := checkpoint.SetManifestIdentitySeedSyncedVersion(ctx, seedSignature); err != nil {
		return Seed{}, err
	}
	return seed, nil
}

func materializeIdentitySeed(workspaceID string, seed Seed) (Seed, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return Seed{}, fmt.Errorf("materialize identity seed: workspace ID is required")
	}
	// Materialization rewrites semantic source aliases into canonical business
	// identifiers. Clone every slice first so callers can safely materialize the
	// same source seed for more than one workspace.
	seed.Roles = append([]identitymodel.IdentityRole(nil), seed.Roles...)
	seed.OrganizationUnits = append([]identitymodel.IdentityOrganizationUnit(nil), seed.OrganizationUnits...)
	seed.Users = append([]identitymodel.IdentityUser(nil), seed.Users...)
	seed.UserRoles = append([]identitymodel.IdentityUserRoleAssignment(nil), seed.UserRoles...)
	seed.Menus = append([]identitymodel.IdentityMenu(nil), seed.Menus...)
	seed.RoleMenus = append([]identitymodel.IdentityRoleMenuAssignment(nil), seed.RoleMenus...)
	roleIDs := make(map[string]string, len(seed.Roles)*2)
	for index := range seed.Roles {
		alias := strings.TrimSpace(seed.Roles[index].RoleID)
		if alias == "" {
			alias = strings.TrimSpace(seed.Roles[index].Key)
		}
		id, err := entityid.Derive("role", "identity.workspace-role", workspaceID, alias)
		if err != nil {
			return Seed{}, err
		}
		roleIDs[alias], roleIDs[strings.TrimSpace(seed.Roles[index].Key)] = id, id
		seed.Roles[index].RoleID = id
	}

	organizationIDs := make(map[string]string, len(seed.OrganizationUnits))
	for index := range seed.OrganizationUnits {
		alias := strings.TrimSpace(seed.OrganizationUnits[index].OrganizationUnitID)
		id, err := entityid.Derive("orgunit", "identity.manifest-organization-unit", workspaceID, alias)
		if err != nil {
			return Seed{}, err
		}
		organizationIDs[alias] = id
		seed.OrganizationUnits[index].OrganizationUnitID = id
	}
	for index := range seed.OrganizationUnits {
		unit := &seed.OrganizationUnits[index]
		if unit.ParentID != nil {
			if parentID := organizationIDs[strings.TrimSpace(*unit.ParentID)]; parentID != "" {
				unit.ParentID = &parentID
			}
		}
		for ancestorIndex, ancestorID := range unit.AncestorIDs {
			if resolved := organizationIDs[strings.TrimSpace(ancestorID)]; resolved != "" {
				unit.AncestorIDs[ancestorIndex] = resolved
			}
		}
		unit.Path = identityOrganizationUnitSeedPath(unit.OrganizationUnitID, unit.AncestorIDs)
	}

	userIDs := make(map[string]string, len(seed.Users))
	for index := range seed.Users {
		alias := strings.TrimSpace(seed.Users[index].UserID)
		id, err := entityid.Derive("user", "identity.manifest-user", workspaceID, alias)
		if err != nil {
			return Seed{}, err
		}
		userIDs[alias] = id
		seed.Users[index].UserID = id
	}
	for index := range seed.Users {
		user := &seed.Users[index]
		user.OrgID = identityMappedSeedID(organizationIDs, user.OrgID)
		user.SupportOrgID = identityMappedSeedID(organizationIDs, user.SupportOrgID)
		user.ManagerUserID = identityMappedSeedID(userIDs, user.ManagerUserID)
	}
	seed.Users = manifestIdentityUserReportingPaths(seed.Users)

	menuIDs := make(map[string]string, len(seed.Menus)*2)
	for index := range seed.Menus {
		alias := strings.TrimSpace(seed.Menus[index].MenuID)
		key := strings.TrimSpace(seed.Menus[index].Key)
		id, err := entityid.Derive("menu", "identity.workspace-menu", workspaceID, key)
		if err != nil {
			return Seed{}, err
		}
		menuIDs[alias], menuIDs[key] = id, id
		seed.Menus[index].MenuID = id
	}
	for index := range seed.Menus {
		seed.Menus[index].ParentID = identityMappedSeedID(menuIDs, seed.Menus[index].ParentID)
	}
	for index := range seed.UserRoles {
		seed.UserRoles[index].UserID = identityMappedSeedID(userIDs, seed.UserRoles[index].UserID)
		seed.UserRoles[index].RoleID = identityMappedSeedID(roleIDs, seed.UserRoles[index].RoleID)
	}
	for index := range seed.RoleMenus {
		seed.RoleMenus[index].RoleID = identityMappedSeedID(roleIDs, seed.RoleMenus[index].RoleID)
		seed.RoleMenus[index].MenuID = identityMappedSeedID(menuIDs, seed.RoleMenus[index].MenuID)
	}
	return seed, nil
}

func identityMappedSeedID(index map[string]string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if resolved := index[value]; resolved != "" {
		return resolved
	}
	return value
}

func identityOrganizationUnitSeedPath(id string, ancestorIDs []string) string {
	parts := append(append([]string(nil), ancestorIDs...), id)
	return "/" + strings.Join(parts, "/")
}

func preserveExistingImplicitSeedUsers(ctx context.Context, identityStore identityrepository.IdentitySeedRepository, manifest manifestmodel.ManifestSchema, seed Seed) (Seed, error) {
	reader, ok := identityStore.(identitySeedUserReader)
	if !ok {
		return seed, nil
	}
	workspaceID := manifestIdentityWorkspaceID(ctx)
	declaredUserIDs := manifestDeclaredIdentityUserIDs(workspaceID, manifest)
	users := make([]identitymodel.IdentityUser, 0, len(seed.Users))
	deletedIDs := map[string]bool{}
	for _, user := range seed.Users {
		existing, found, err := reader.GetIdentityUser(ctx, workspaceID, user.UserID)
		if err != nil {
			return Seed{}, fmt.Errorf("load implicit identity seed user %s: %w", user.UserID, err)
		}
		// An account lifecycle decision wins over source seed defaults. Do not
		// resurrect the user or its role grants on a later manifest refresh.
		if found && existing.Status == identitymodel.IdentityStatusDeleted {
			deletedIDs[user.UserID] = true
			continue
		}
		if found && !declaredUserIDs[strings.TrimSpace(user.UserID)] {
			user = existing
		}
		users = append(users, user)
	}
	seed.Users = users
	assignments := make([]identitymodel.IdentityUserRoleAssignment, 0, len(seed.UserRoles))
	for _, assignment := range seed.UserRoles {
		if !deletedIDs[assignment.UserID] {
			assignments = append(assignments, assignment)
		}
	}
	seed.UserRoles = assignments
	return seed, nil
}

func manifestDeclaredIdentityUserIDs(workspaceID string, manifest manifestmodel.ManifestSchema) map[string]bool {
	declared := map[string]bool{}
	for _, user := range manifest.Users {
		if id, err := entityid.Derive("user", "identity.manifest-user", workspaceID, user.ID); err == nil {
			declared[id] = true
		}
	}
	if manifest.IdentityBootstrap != nil {
		for _, user := range manifest.IdentityBootstrap.Users {
			if id, err := entityid.Derive("user", "identity.manifest-user", workspaceID, user.ID); err == nil {
				declared[id] = true
			}
		}
	}
	return declared
}

func manifestIdentityWorkspaceID(ctx context.Context) string {
	return requestcontext.WorkspaceID(ctx)
}

func retireRemovedPlatformIdentityMenus(ctx context.Context, identityStore identityrepository.IdentitySeedRepository) error {
	retiredKeys := map[string]bool{
		"org_permissions":          true,
		"identity_permission_list": true,
		"runtime_operations":       true,
		"system":                   true,
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
			retiredIDs[menu.MenuID] = true
		}
	}
	removed := map[string]bool{}
	var removeTree func(string) error
	removeTree = func(parentID string) error {
		if removed[parentID] {
			return nil
		}
		for _, child := range byParent[parentID] {
			if err := removeTree(child.MenuID); err != nil {
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

// Generated seed accounts use a stable workspace namespace. Explicit login
// names are preserved and must pass the same user-table uniqueness constraint
// as public account creation. Existing implicit seed users remain unchanged.
func scopeGeneratedSeedLoginNames(ctx context.Context, store identityrepository.IdentitySeedRepository, manifest manifestmodel.ManifestSchema, seed Seed, workspaceID string) (Seed, error) {
	availability, ok := store.(interface {
		GlobalLoginNameAvailable(context.Context, string, string, string) (bool, error)
	})
	if !ok {
		return seed, nil
	}
	reader, _ := store.(identitySeedUserReader)
	explicit := map[string]bool{}
	for _, user := range manifest.Users {
		if strings.TrimSpace(user.Email) != "" {
			if id, err := entityid.Derive("user", "identity.manifest-user", workspaceID, user.ID); err == nil {
				explicit[id] = true
			}
		}
	}
	if manifest.IdentityBootstrap != nil {
		for _, user := range manifest.IdentityBootstrap.Users {
			if strings.TrimSpace(user.Email) != "" {
				if id, err := entityid.Derive("user", "identity.manifest-user", workspaceID, user.ID); err == nil {
					explicit[id] = true
				}
			}
		}
	}
	digest := sha256.Sum256([]byte(workspaceID))
	suffix := hex.EncodeToString(digest[:12])
	users := append([]identitymodel.IdentityUser(nil), seed.Users...)
	for index, user := range users {
		if explicit[user.UserID] {
			continue
		}
		if reader != nil {
			existing, found, err := reader.GetIdentityUser(ctx, workspaceID, user.UserID)
			if err != nil {
				return Seed{}, err
			}
			if found {
				users[index].Email = existing.Email
				continue
			}
		}
		available, err := availability.GlobalLoginNameAvailable(ctx, workspaceID, user.UserID, user.Email)
		if err != nil {
			return Seed{}, err
		}
		if available {
			continue
		}
		local, domain, ok := strings.Cut(user.Email, "@")
		if !ok {
			local, domain = user.UserID, "example.com"
		}
		users[index].Email = local + "+" + suffix + "@" + domain
	}
	seed.Users = users
	return seed, nil
}
