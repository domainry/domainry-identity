package scim

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"reflect"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/mutation"
	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
	scimrepository "github.com/domainry/domainry-identity/internal/domain/scim/repository"
	"github.com/google/uuid"
)

type Service struct {
	identity     *identityapplication.IdentityApplicationService
	sessions     identityapplication.IdentitySessionRevoker
	store        scimrepository.Repository
	transactions transactionManager
}

type transactionManager interface {
	WithinIdentityTransaction(context.Context, func(context.Context) error) error
}

func NewService(identity *identityapplication.IdentityApplicationService, sessions identityapplication.IdentitySessionRevoker, store scimrepository.Repository, transactions transactionManager) (*Service, error) {
	if identity == nil || sessions == nil || store == nil || transactions == nil {
		return nil, fmt.Errorf("SCIM identity, session revoker, repository, and transaction manager are required")
	}
	return &Service{identity: identity, sessions: sessions, store: store, transactions: transactions}, nil
}

func (s *Service) ListUsers(ctx context.Context, filter string) ([]scimmodel.User, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	links, err := s.store.ListUserLinks(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	users, err := s.identity.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]identitymodel.IdentityUser, len(users))
	for _, user := range users {
		byID[user.UserID] = user
	}
	result := make([]scimmodel.User, 0, len(links))
	for _, link := range links {
		user, found := byID[link.UserID]
		if !found || user.Status == identitymodel.IdentityStatusDeleted {
			continue
		}
		resource := projectUser(user, link)
		matches, matchErr := MatchFilter(filter, UserAttributeValues(resource))
		if matchErr != nil {
			return nil, matchErr
		}
		if matches {
			result = append(result, resource)
		}
	}
	return result, nil
}

func (s *Service) GetUser(ctx context.Context, userID string) (scimmodel.User, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.User{}, err
	}
	link, found, err := s.store.GetUserLink(ctx, workspaceID, strings.TrimSpace(userID))
	if err != nil {
		return scimmodel.User{}, err
	}
	if !found {
		return scimmodel.User{}, notFound("SCIM user was not found")
	}
	user, found, err := s.identity.UserByID(ctx, link.UserID)
	if err != nil {
		return scimmodel.User{}, err
	}
	if !found || user.Status == identitymodel.IdentityStatusDeleted {
		return scimmodel.User{}, notFound("SCIM user was not found")
	}
	return projectUser(user, link), nil
}

func (s *Service) CreateUser(ctx context.Context, resource scimmodel.User) (scimmodel.User, error) {
	if err := validateResourceSchemas(resource.Schemas, scimmodel.SchemaUser, resource.EnterpriseUser != nil); err != nil {
		return scimmodel.User{}, err
	}
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.User{}, err
	}
	userName := strings.TrimSpace(resource.UserName)
	if userName == "" {
		return scimmodel.User{}, invalidValue("userName is required")
	}
	err = s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		deletedLink, restoring, linkErr := s.store.GetDeletedUserLinkByUserName(transactionContext, workspaceID, userName)
		if linkErr != nil {
			return linkErr
		}
		resource.ID = uuid.NewString()
		existing := identitymodel.IdentityUser{UserID: resource.ID}
		if restoring {
			resource.ID = deletedLink.UserID
			var found bool
			existing, found, linkErr = s.identity.UserByID(transactionContext, deletedLink.UserID)
			if linkErr != nil {
				return linkErr
			}
			if !found || existing.Status == identitymodel.IdentityStatusDeleted {
				return &Error{Status: 409, SCIMType: "uniqueness", Detail: "deleted SCIM user cannot be restored because its Identity subject is unavailable"}
			}
		}
		user, normalizedUserName, conversionErr := identityUserFromSCIM(resource, existing)
		if conversionErr != nil {
			return conversionErr
		}
		if uniqueErr := s.ensureUserUnique(transactionContext, workspaceID, resource.ID, normalizedUserName); uniqueErr != nil {
			return uniqueErr
		}
		if identityErr := s.identity.UpsertUser(transactionContext, user); identityErr != nil {
			return translateIdentityError(identityErr)
		}
		link := scimmodel.UserLink{WorkspaceID: workspaceID, UserID: resource.ID, UserName: normalizedUserName, ExternalID: strings.TrimSpace(resource.ExternalID), Department: scimDepartment(resource)}
		if restoring {
			restored, restoreErr := s.store.RestoreUserLink(transactionContext, link, deletedLink.Version)
			if restoreErr != nil {
				return translateDirectoryError(restoreErr, "userName already belongs to another SCIM user")
			}
			if !restored {
				return preconditionFailed("deleted SCIM user changed during restore")
			}
			return nil
		}
		if linkErr := s.store.CreateUserLink(transactionContext, link); linkErr != nil {
			return translateDirectoryError(linkErr, "SCIM user already exists")
		}
		return nil
	})
	if err != nil {
		return scimmodel.User{}, err
	}
	return s.GetUser(ctx, resource.ID)
}

func (s *Service) ReplaceUser(ctx context.Context, userID string, resource scimmodel.User, expectedETag string) (scimmodel.User, error) {
	if err := validateResourceSchemas(resource.Schemas, scimmodel.SchemaUser, resource.EnterpriseUser != nil); err != nil {
		return scimmodel.User{}, err
	}
	existing, err := s.GetUser(ctx, userID)
	if err != nil {
		return scimmodel.User{}, err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return scimmodel.User{}, err
	}
	resource.ID = existing.ID
	return s.replaceUser(ctx, existing, resource)
}

func (s *Service) PatchUser(ctx context.Context, userID string, patch scimmodel.PatchRequest, expectedETag string) (scimmodel.User, error) {
	existing, err := s.GetUser(ctx, userID)
	if err != nil {
		return scimmodel.User{}, err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return scimmodel.User{}, err
	}
	updated, err := ApplyUserPatch(existing, patch)
	if err != nil {
		return scimmodel.User{}, err
	}
	if reflect.DeepEqual(existing, updated) {
		return existing, nil
	}
	return s.replaceUser(ctx, existing, updated)
}

func (s *Service) replaceUser(ctx context.Context, existing, resource scimmodel.User) (scimmodel.User, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.User{}, err
	}
	err = s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		currentResource, currentErr := s.GetUser(transactionContext, existing.ID)
		if currentErr != nil {
			return currentErr
		}
		if currentResource.Meta.Version != existing.Meta.Version {
			return preconditionFailed("SCIM user changed during update")
		}
		current, found, identityErr := s.identity.UserByID(transactionContext, existing.ID)
		if identityErr != nil {
			return identityErr
		}
		if !found {
			return notFound("SCIM user was not found")
		}
		user, userName, conversionErr := identityUserFromSCIM(resource, current)
		if conversionErr != nil {
			return conversionErr
		}
		if uniqueErr := s.ensureUserUnique(transactionContext, workspaceID, existing.ID, userName); uniqueErr != nil {
			return uniqueErr
		}
		if identityErr := s.identity.UpsertUser(transactionContext, user); identityErr != nil {
			return translateIdentityError(identityErr)
		}
		if user.Status == identitymodel.IdentityStatusDisabled {
			if _, disableErr := s.identity.DisableUser(transactionContext, user.UserID, s.sessions); disableErr != nil {
				return translateIdentityError(disableErr)
			}
		}
		link, found, linkErr := s.store.GetUserLink(transactionContext, workspaceID, existing.ID)
		if linkErr != nil {
			return linkErr
		}
		if !found {
			return notFound("SCIM user was not found")
		}
		link.UserName, link.ExternalID, link.Department = userName, strings.TrimSpace(resource.ExternalID), scimDepartment(resource)
		updated, linkErr := s.store.UpdateUserLink(transactionContext, link, link.Version)
		if linkErr != nil {
			return translateDirectoryError(linkErr, "userName already belongs to another SCIM user")
		}
		if !updated {
			return preconditionFailed("SCIM user changed during update")
		}
		return nil
	})
	if err != nil {
		return scimmodel.User{}, err
	}
	return s.GetUser(ctx, existing.ID)
}

func (s *Service) DeleteUser(ctx context.Context, userID, expectedETag string) error {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return err
	}
	existing, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return err
	}
	return s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		current, currentErr := s.GetUser(transactionContext, existing.ID)
		if currentErr != nil {
			return currentErr
		}
		if current.Meta.Version != existing.Meta.Version {
			return preconditionFailed("SCIM user changed during delete")
		}
		if _, disableErr := s.identity.DisableUser(transactionContext, existing.ID, s.sessions); disableErr != nil {
			return translateIdentityError(disableErr)
		}
		link, found, linkErr := s.store.GetUserLink(transactionContext, workspaceID, existing.ID)
		if linkErr != nil {
			return linkErr
		}
		if !found {
			return notFound("SCIM user was not found")
		}
		deleted, linkErr := s.store.DeleteUserLink(transactionContext, workspaceID, existing.ID, link.Version)
		if linkErr != nil {
			return linkErr
		}
		if !deleted {
			return preconditionFailed("SCIM user changed during delete")
		}
		return nil
	})
}

func (s *Service) ListGroups(ctx context.Context, filter string) ([]scimmodel.Group, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := s.store.ListGroups(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	users, err := s.ListUsers(ctx, "")
	if err != nil {
		return nil, err
	}
	userByID := make(map[string]scimmodel.User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}
	result := make([]scimmodel.Group, 0, len(groups))
	for _, group := range groups {
		resource := projectGroup(group, userByID)
		matches, matchErr := MatchFilter(filter, GroupAttributeValues(resource))
		if matchErr != nil {
			return nil, matchErr
		}
		if matches {
			result = append(result, resource)
		}
	}
	return result, nil
}

func (s *Service) GetGroup(ctx context.Context, groupID string) (scimmodel.Group, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.Group{}, err
	}
	group, found, err := s.store.GetGroup(ctx, workspaceID, strings.TrimSpace(groupID))
	if err != nil {
		return scimmodel.Group{}, err
	}
	if !found {
		return scimmodel.Group{}, notFound("SCIM group was not found")
	}
	users, err := s.ListUsers(ctx, "")
	if err != nil {
		return scimmodel.Group{}, err
	}
	byID := make(map[string]scimmodel.User, len(users))
	for _, user := range users {
		byID[user.ID] = user
	}
	return projectGroup(group, byID), nil
}

func (s *Service) CreateGroup(ctx context.Context, resource scimmodel.Group) (scimmodel.Group, error) {
	if err := validateResourceSchemas(resource.Schemas, scimmodel.SchemaGroup, false); err != nil {
		return scimmodel.Group{}, err
	}
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.Group{}, err
	}
	resource.ID = uuid.NewString()
	err = s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		group, groupErr := s.directoryGroup(transactionContext, workspaceID, resource)
		if groupErr != nil {
			return groupErr
		}
		if groupErr := s.store.CreateGroup(transactionContext, group); groupErr != nil {
			return translateDirectoryError(groupErr, "SCIM group already exists")
		}
		return nil
	})
	if err != nil {
		return scimmodel.Group{}, err
	}
	return s.GetGroup(ctx, resource.ID)
}

func (s *Service) ReplaceGroup(ctx context.Context, groupID string, resource scimmodel.Group, expectedETag string) (scimmodel.Group, error) {
	if err := validateResourceSchemas(resource.Schemas, scimmodel.SchemaGroup, false); err != nil {
		return scimmodel.Group{}, err
	}
	existing, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return scimmodel.Group{}, err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return scimmodel.Group{}, err
	}
	resource.ID = existing.ID
	return s.replaceGroup(ctx, existing, resource)
}

func (s *Service) PatchGroup(ctx context.Context, groupID string, patch scimmodel.PatchRequest, expectedETag string) (scimmodel.Group, error) {
	existing, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return scimmodel.Group{}, err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return scimmodel.Group{}, err
	}
	updated, err := ApplyGroupPatch(existing, patch)
	if err != nil {
		return scimmodel.Group{}, err
	}
	if reflect.DeepEqual(existing, updated) {
		return existing, nil
	}
	return s.replaceGroup(ctx, existing, updated)
}

func (s *Service) replaceGroup(ctx context.Context, existing, resource scimmodel.Group) (scimmodel.Group, error) {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return scimmodel.Group{}, err
	}
	err = s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		currentResource, currentErr := s.GetGroup(transactionContext, existing.ID)
		if currentErr != nil {
			return currentErr
		}
		if currentResource.Meta.Version != existing.Meta.Version {
			return preconditionFailed("SCIM group changed during update")
		}
		group, groupErr := s.directoryGroup(transactionContext, workspaceID, resource)
		if groupErr != nil {
			return groupErr
		}
		current, found, groupErr := s.store.GetGroup(transactionContext, workspaceID, existing.ID)
		if groupErr != nil {
			return groupErr
		}
		if !found {
			return notFound("SCIM group was not found")
		}
		group.Version = current.Version
		updated, groupErr := s.store.UpdateGroup(transactionContext, group, current.Version)
		if groupErr != nil {
			return groupErr
		}
		if !updated {
			return preconditionFailed("SCIM group changed during update")
		}
		return nil
	})
	if err != nil {
		return scimmodel.Group{}, err
	}
	return s.GetGroup(ctx, existing.ID)
}

func (s *Service) DeleteGroup(ctx context.Context, groupID, expectedETag string) error {
	workspaceID, err := workspace(ctx)
	if err != nil {
		return err
	}
	existing, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if err := requireETag(expectedETag, existing.Meta.Version); err != nil {
		return err
	}
	return s.transactions.WithinIdentityTransaction(ctx, func(transactionContext context.Context) error {
		currentResource, currentErr := s.GetGroup(transactionContext, existing.ID)
		if currentErr != nil {
			return currentErr
		}
		if currentResource.Meta.Version != existing.Meta.Version {
			return preconditionFailed("SCIM group changed during delete")
		}
		current, found, groupErr := s.store.GetGroup(transactionContext, workspaceID, existing.ID)
		if groupErr != nil {
			return groupErr
		}
		if !found {
			return notFound("SCIM group was not found")
		}
		deleted, groupErr := s.store.DeleteGroup(transactionContext, workspaceID, existing.ID, current.Version)
		if groupErr != nil {
			return groupErr
		}
		if !deleted {
			return preconditionFailed("SCIM group changed during delete")
		}
		return nil
	})
}

func (s *Service) directoryGroup(ctx context.Context, workspaceID string, resource scimmodel.Group) (scimmodel.DirectoryGroup, error) {
	displayName := strings.TrimSpace(resource.DisplayName)
	if displayName == "" {
		return scimmodel.DirectoryGroup{}, invalidValue("displayName is required")
	}
	memberIDs := make([]string, 0, len(resource.Members))
	seen := map[string]struct{}{}
	for _, member := range resource.Members {
		memberID := strings.TrimSpace(member.Value)
		if memberID == "" {
			return scimmodel.DirectoryGroup{}, invalidValue("group member value is required")
		}
		if _, duplicate := seen[memberID]; duplicate {
			continue
		}
		if _, err := s.GetUser(ctx, memberID); err != nil {
			var scimErr *Error
			if errors.As(err, &scimErr) && scimErr.Status == 404 {
				return scimmodel.DirectoryGroup{}, invalidValue("group member does not identify an existing SCIM user")
			}
			return scimmodel.DirectoryGroup{}, err
		}
		seen[memberID] = struct{}{}
		memberIDs = append(memberIDs, memberID)
	}
	sort.Strings(memberIDs)
	return scimmodel.DirectoryGroup{WorkspaceID: workspaceID, GroupID: strings.TrimSpace(resource.ID), ExternalID: strings.TrimSpace(resource.ExternalID), DisplayName: displayName, MemberIDs: memberIDs}, nil
}

func (s *Service) ensureUserUnique(ctx context.Context, workspaceID, exceptID, userName string) error {
	links, err := s.store.ListUserLinks(ctx, workspaceID)
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.UserID == exceptID {
			continue
		}
		if strings.EqualFold(link.UserName, userName) {
			return conflict("userName already belongs to another SCIM user")
		}
	}
	return nil
}

func identityUserFromSCIM(resource scimmodel.User, existing identitymodel.IdentityUser) (identitymodel.IdentityUser, string, error) {
	userName := strings.TrimSpace(resource.UserName)
	if userName == "" {
		return identitymodel.IdentityUser{}, "", invalidValue("userName is required")
	}
	email := primaryValue(resource.Emails)
	if email == "" {
		if address, err := mail.ParseAddress(userName); err == nil && strings.EqualFold(address.Address, userName) {
			email = userName
		}
	}
	if address, err := mail.ParseAddress(email); email == "" || err != nil || !strings.EqualFold(address.Address, email) {
		return identitymodel.IdentityUser{}, "", invalidValue("a valid primary email address is required")
	}
	displayName := strings.TrimSpace(resource.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(resource.Name.Formatted)
	}
	if displayName == "" {
		displayName = strings.TrimSpace(strings.Join([]string{resource.Name.GivenName, resource.Name.FamilyName}, " "))
	}
	if displayName == "" {
		displayName = userName
	}
	active := true
	if resource.Active != nil {
		active = *resource.Active
	}
	existing.UserID = strings.TrimSpace(resource.ID)
	existing.Name = displayName
	existing.GivenName = strings.TrimSpace(resource.Name.GivenName)
	existing.MiddleName = strings.TrimSpace(resource.Name.MiddleName)
	existing.FamilyName = strings.TrimSpace(resource.Name.FamilyName)
	existing.NamePrefix = strings.TrimSpace(resource.Name.HonorificPrefix)
	existing.NameSuffix = strings.TrimSpace(resource.Name.HonorificSuffix)
	existing.Email = strings.ToLower(strings.TrimSpace(email))
	existing.Phone = primaryValue(resource.PhoneNumbers)
	existing.AccountType = identitymodel.IdentityAccountHuman
	existing.Locale = firstNonEmpty(resource.Locale, resource.PreferredLang, "en-US")
	existing.Timezone = strings.TrimSpace(resource.Timezone)
	existing.Status = identitymodel.IdentityStatusActive
	if !active {
		existing.Status = identitymodel.IdentityStatusDisabled
	}
	existing.WorkerNo = ""
	existing.ManagerUserID = ""
	if resource.EnterpriseUser != nil {
		existing.WorkerNo = strings.TrimSpace(resource.EnterpriseUser.EmployeeNumber)
		if resource.EnterpriseUser.Manager != nil {
			existing.ManagerUserID = strings.TrimSpace(resource.EnterpriseUser.Manager.Value)
		}
	}
	return existing, userName, nil
}

func projectUser(user identitymodel.IdentityUser, link scimmodel.UserLink) scimmodel.User {
	active := user.Status == identitymodel.IdentityStatusActive
	schemas := []string{scimmodel.SchemaUser}
	enterprise := &scimmodel.EnterpriseUser{EmployeeNumber: user.WorkerNo, Department: link.Department}
	if user.ManagerUserID != "" {
		enterprise.Manager = &scimmodel.Manager{Value: user.ManagerUserID, Ref: "/scim/v2/Users/" + user.ManagerUserID}
	}
	if enterprise.EmployeeNumber == "" && enterprise.Department == "" && enterprise.Manager == nil {
		enterprise = nil
	} else {
		schemas = append(schemas, scimmodel.SchemaEnterpriseUser)
	}
	resource := scimmodel.User{
		Schemas: schemas, ID: user.UserID, ExternalID: link.ExternalID, UserName: link.UserName,
		Name:        scimmodel.Name{Formatted: user.Name, FamilyName: user.FamilyName, GivenName: user.GivenName, MiddleName: user.MiddleName, HonorificPrefix: user.NamePrefix, HonorificSuffix: user.NameSuffix},
		DisplayName: user.Name, Active: &active, PreferredLang: user.Locale, Locale: user.Locale, Timezone: user.Timezone, EnterpriseUser: enterprise,
		Meta: scimmodel.Meta{ResourceType: "User", Created: link.CreatedAt, LastModified: latestTimestamp(user.UpdatedAt, link.UpdatedAt), Version: versionETag(link.Version, user.Version), Location: "/scim/v2/Users/" + user.UserID},
	}
	if user.Email != "" {
		resource.Emails = []scimmodel.MultiValue{{Value: user.Email, Type: "work", Primary: true}}
	}
	if user.Phone != "" {
		resource.PhoneNumbers = []scimmodel.MultiValue{{Value: user.Phone, Type: "work", Primary: true}}
	}
	return resource
}

func projectGroup(group scimmodel.DirectoryGroup, users map[string]scimmodel.User) scimmodel.Group {
	members := make([]scimmodel.Member, 0, len(group.MemberIDs))
	for _, userID := range group.MemberIDs {
		user, found := users[userID]
		if !found {
			continue
		}
		members = append(members, scimmodel.Member{Value: userID, Ref: "/scim/v2/Users/" + userID, Display: user.DisplayName, Type: "User"})
	}
	return scimmodel.Group{
		Schemas: []string{scimmodel.SchemaGroup}, ID: group.GroupID, ExternalID: group.ExternalID, DisplayName: group.DisplayName, Members: members,
		Meta: scimmodel.Meta{ResourceType: "Group", Created: group.CreatedAt, LastModified: group.UpdatedAt, Version: versionETag(group.Version), Location: "/scim/v2/Groups/" + group.GroupID},
	}
}

func primaryValue(values []scimmodel.MultiValue) string {
	for _, value := range values {
		if value.Primary && strings.TrimSpace(value.Value) != "" {
			return strings.TrimSpace(value.Value)
		}
	}
	for _, value := range values {
		if strings.TrimSpace(value.Value) != "" {
			return strings.TrimSpace(value.Value)
		}
	}
	return ""
}

func scimDepartment(resource scimmodel.User) string {
	if resource.EnterpriseUser == nil {
		return ""
	}
	return strings.TrimSpace(resource.EnterpriseUser.Department)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func validateResourceSchemas(schemas []string, required string, enterpriseAttributes bool) error {
	foundRequired, foundEnterprise := false, false
	for _, schema := range schemas {
		switch strings.TrimSpace(schema) {
		case required:
			foundRequired = true
		case scimmodel.SchemaEnterpriseUser:
			if required != scimmodel.SchemaUser {
				return invalidValue("resource contains an unsupported schemas URI")
			}
			foundEnterprise = true
		default:
			return invalidValue("resource contains an unsupported schemas URI")
		}
	}
	if !foundRequired {
		return invalidValue("resource schemas must include " + required)
	}
	if enterpriseAttributes && !foundEnterprise {
		return invalidValue("enterprise user attributes require the enterprise User schema URI")
	}
	return nil
}

func latestTimestamp(values ...string) string {
	latest := ""
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value > latest {
			latest = value
		}
	}
	return latest
}

func workspace(ctx context.Context) (string, error) {
	workspaceID := strings.TrimSpace(requestcontext.WorkspaceID(ctx))
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return "", &Error{Status: 401, Detail: "SCIM bearer token does not resolve a workspace", Cause: err}
	}
	return workspaceID, nil
}

func versionETag(versions ...int64) string {
	parts := make([]string, 0, len(versions))
	for _, version := range versions {
		parts = append(parts, fmt.Sprintf("%d", version))
	}
	return `W/"` + strings.Join(parts, "-") + `"`
}

func requireETag(expected, actual string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	for _, candidate := range strings.Split(expected, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == actual {
			return nil
		}
	}
	return preconditionFailed("If-Match does not match the current resource version")
}

func translateIdentityError(err error) error {
	if err == nil {
		return nil
	}
	switch apperror.KindOf(err) {
	case apperror.KindBadRequest:
		return &Error{Status: 400, SCIMType: "invalidValue", Detail: "SCIM resource violates Identity user constraints", Cause: err}
	case apperror.KindConflict:
		return &Error{Status: 409, SCIMType: "uniqueness", Detail: "SCIM resource conflicts with an existing Identity user", Cause: err}
	case apperror.KindNotFound:
		return notFound("SCIM resource target was not found")
	default:
		return err
	}
}

func translateDirectoryError(err error, detail string) error {
	if mutation.IsMutationConflict(err, mutation.MutationConflictUnique) {
		return &Error{Status: 409, SCIMType: "uniqueness", Detail: detail, Cause: err}
	}
	return err
}
