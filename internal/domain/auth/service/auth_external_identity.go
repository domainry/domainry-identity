package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"fmt"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) ExternalLogin(ctx context.Context, workspaceID string, assertion authmodel.AuthExternalIdentityAssertion, autoCreateUser bool) (authmodel.AuthSession, error) {
	return s.ExternalLoginWithPolicy(ctx, workspaceID, assertion, authmodel.AuthExternalLoginPolicy{AutoCreateUsers: autoCreateUser})
}

func (s *AuthDomainService) ExternalLoginWithPolicy(ctx context.Context, workspaceID string, assertion authmodel.AuthExternalIdentityAssertion, policy authmodel.AuthExternalLoginPolicy) (authmodel.AuthSession, error) {
	return s.ExternalLoginWithPolicyForApplication(ctx, workspaceID, assertion, policy, s.audience)
}

func (s *AuthDomainService) ExternalLoginWithPolicyForApplication(ctx context.Context, workspaceID string, assertion authmodel.AuthExternalIdentityAssertion, policy authmodel.AuthExternalLoginPolicy, applicationKey string) (authmodel.AuthSession, error) {
	assertion.Provider = normalizeProvider(assertion.Provider)
	assertion.Subject = strings.TrimSpace(assertion.Subject)
	if assertion.Provider == "" || assertion.Subject == "" {
		return authmodel.AuthSession{}, forbidden("auth.external_account_unlinked")
	}
	account, ok, err := s.externalAccountByProviderSubject(ctx, workspaceID, assertion.Provider, assertion.Subject)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if ok {
		user, ok, err := s.identity.UserByID(ctx, account.UserID)
		if err != nil {
			return authmodel.AuthSession{}, err
		}
		if !ok || user.Status != identitymodel.IdentityStatusActive {
			return authmodel.AuthSession{}, forbidden("auth.user_disabled")
		}
		return s.issueSessionForAudience(ctx, workspaceID, user, applicationKey)
	}
	if !policy.AutoCreateUsers {
		return authmodel.AuthSession{}, forbidden("auth.external_account_unlinked")
	}
	if user, ok, err := s.externalLoginUserByVerifiedEmail(ctx, assertion); err != nil {
		return authmodel.AuthSession{}, err
	} else if ok {
		account = identitymodel.IdentityExternalAccount{
			ID:              "ext_" + randomToken(),
			UserID:          user.ID,
			Provider:        assertion.Provider,
			ProviderSubject: assertion.Subject,
			Email:           strings.TrimSpace(assertion.Email),
			Phone:           strings.TrimSpace(assertion.Phone),
			DisplayName:     strings.TrimSpace(assertion.DisplayName),
			AvatarURL:       strings.TrimSpace(assertion.AvatarURL),
			Metadata:        strings.TrimSpace(assertion.Metadata),
			LinkedAt:        time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.identityStore.UpsertIdentityExternalAccount(ctx, workspaceID, account); err != nil {
			return authmodel.AuthSession{}, err
		}
		return s.issueSessionForAudience(ctx, workspaceID, user, applicationKey)
	}
	user, err := s.createExternalIdentityUser(ctx, assertion, policy)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	account = identitymodel.IdentityExternalAccount{
		ID:              "ext_" + randomToken(),
		UserID:          user.ID,
		Provider:        assertion.Provider,
		ProviderSubject: assertion.Subject,
		Email:           strings.TrimSpace(assertion.Email),
		Phone:           strings.TrimSpace(assertion.Phone),
		DisplayName:     strings.TrimSpace(assertion.DisplayName),
		AvatarURL:       strings.TrimSpace(assertion.AvatarURL),
		Metadata:        strings.TrimSpace(assertion.Metadata),
		LinkedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.identityStore.UpsertIdentityExternalAccount(ctx, workspaceID, account); err != nil {
		return authmodel.AuthSession{}, err
	}
	return s.issueSessionForAudience(ctx, workspaceID, user, applicationKey)
}

func (s *AuthDomainService) externalLoginUserByVerifiedEmail(ctx context.Context, assertion authmodel.AuthExternalIdentityAssertion) (identitymodel.IdentityUser, bool, error) {
	email := strings.TrimSpace(assertion.Email)
	if email == "" {
		return identitymodel.IdentityUser{}, false, nil
	}
	user, ok, err := s.identity.UserByLogin(ctx, email)
	if err != nil || !ok {
		return identitymodel.IdentityUser{}, ok, err
	}
	if user.Status != identitymodel.IdentityStatusActive {
		return identitymodel.IdentityUser{}, false, forbidden("auth.user_disabled")
	}
	return user, true, nil
}

func (s *AuthDomainService) ListExternalAccounts(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityExternalAccount, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, forbidden("auth.token_required")
	}
	return s.identityStore.ListIdentityExternalAccounts(ctx, workspaceID, userID)
}

func (s *AuthDomainService) BindExternalAccount(ctx context.Context, workspaceID, userID string, assertion authmodel.AuthExternalIdentityAssertion) (identitymodel.IdentityExternalAccount, error) {
	userID = strings.TrimSpace(userID)
	assertion.Provider = normalizeProvider(assertion.Provider)
	assertion.Subject = strings.TrimSpace(assertion.Subject)
	if userID == "" || assertion.Provider == "" || assertion.Subject == "" {
		return identitymodel.IdentityExternalAccount{}, badRequest("auth.external_account_invalid")
	}
	if _, ok, err := s.identity.UserByID(ctx, userID); err != nil {
		return identitymodel.IdentityExternalAccount{}, err
	} else if !ok {
		return identitymodel.IdentityExternalAccount{}, forbidden("auth.user_disabled")
	}
	if existing, ok, err := s.externalAccountByProviderSubject(ctx, workspaceID, assertion.Provider, assertion.Subject); err != nil {
		return identitymodel.IdentityExternalAccount{}, err
	} else if ok {
		if existing.UserID != userID {
			return identitymodel.IdentityExternalAccount{}, forbidden("auth.external_account_already_bound")
		}
		return existing, nil
	}
	account := identitymodel.IdentityExternalAccount{
		ID:              "ext_" + randomToken(),
		UserID:          userID,
		Provider:        assertion.Provider,
		ProviderSubject: assertion.Subject,
		Email:           strings.TrimSpace(assertion.Email),
		Phone:           strings.TrimSpace(assertion.Phone),
		DisplayName:     strings.TrimSpace(assertion.DisplayName),
		AvatarURL:       strings.TrimSpace(assertion.AvatarURL),
		Metadata:        strings.TrimSpace(assertion.Metadata),
		LinkedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.identityStore.UpsertIdentityExternalAccount(ctx, workspaceID, account); err != nil {
		return identitymodel.IdentityExternalAccount{}, err
	}
	return account, nil
}

func (s *AuthDomainService) UnbindExternalAccount(ctx context.Context, workspaceID, userID string, provider string, accountID string) error {
	userID = strings.TrimSpace(userID)
	provider = normalizeProvider(provider)
	accountID = strings.TrimSpace(accountID)
	if userID == "" || provider == "" || accountID == "" {
		return badRequest("auth.external_account_invalid")
	}
	accounts, err := s.identityStore.ListIdentityExternalAccounts(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if account.ID == accountID && normalizeProvider(account.Provider) == provider {
			return s.identityStore.RemoveIdentityExternalAccount(ctx, workspaceID, accountID)
		}
	}
	return forbidden("auth.external_account_not_found")
}

func (s *AuthDomainService) externalAccountByProviderSubject(ctx context.Context, workspaceID, provider string, subject string) (identitymodel.IdentityExternalAccount, bool, error) {
	provider = normalizeProvider(provider)
	subject = strings.TrimSpace(subject)
	accounts, err := s.identityStore.ListIdentityExternalAccounts(ctx, workspaceID, "")
	if err != nil {
		return identitymodel.IdentityExternalAccount{}, false, err
	}
	for _, account := range accounts {
		if normalizeProvider(account.Provider) == provider && strings.TrimSpace(account.ProviderSubject) == subject {
			return account, true, nil
		}
	}
	return identitymodel.IdentityExternalAccount{}, false, nil
}

func (s *AuthDomainService) createExternalIdentityUser(ctx context.Context, assertion authmodel.AuthExternalIdentityAssertion, policy authmodel.AuthExternalLoginPolicy) (identitymodel.IdentityUser, error) {
	email := strings.TrimSpace(assertion.Email)
	if email == "" {
		return identitymodel.IdentityUser{}, badRequest("auth.external_email_required")
	}
	idBase := assertion.Provider + "_" + assertion.Subject
	idBase = strings.Trim(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return '_'
	}, idBase), "_")
	if idBase == "" {
		idBase = "external_user"
	}
	if len(idBase) > 64 {
		idBase = idBase[:64]
	}
	userID := idBase
	for i := 0; ; i++ {
		if _, ok, err := s.identity.UserByID(ctx, userID); err != nil {
			return identitymodel.IdentityUser{}, err
		} else if !ok {
			break
		}
		userID = fmt.Sprintf("%s_%d", idBase, i+1)
	}
	name := strings.TrimSpace(assertion.DisplayName)
	if name == "" {
		name = email
	}
	user := identitymodel.IdentityUser{
		ID: userID, Name: name, Email: email, Phone: strings.TrimSpace(assertion.Phone), Status: identitymodel.IdentityStatusActive,
	}
	if err := s.identity.UpsertUser(ctx, user); err != nil {
		return identitymodel.IdentityUser{}, err
	}
	role, ok, err := s.roleForExternalAssertion(ctx, assertion, policy)
	if err != nil {
		return identitymodel.IdentityUser{}, err
	}
	if ok {
		if err := s.identity.AssignUserRole(ctx, identitymodel.IdentityUserRoleAssignment{UserID: user.ID, RoleID: role.ID}); err != nil {
			return identitymodel.IdentityUser{}, err
		}
	}
	return user, nil
}

func (s *AuthDomainService) roleForExternalAssertion(ctx context.Context, assertion authmodel.AuthExternalIdentityAssertion, policy authmodel.AuthExternalLoginPolicy) (identitymodel.IdentityRole, bool, error) {
	roles, err := s.identity.ListRoles(ctx)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	byKey := map[string]identitymodel.IdentityRole{}
	for _, role := range roles {
		if _, published := s.identity.PublishedRoleDefinition(ctx, valueOrDefault(role.Key, role.ID)); !published {
			continue
		}
		byKey[strings.ToLower(strings.TrimSpace(role.Key))] = role
		byKey[strings.ToLower(strings.TrimSpace(role.ID))] = role
	}
	for _, mapping := range policy.RoleMappings {
		role, ok := byKey[strings.ToLower(strings.TrimSpace(mapping.RoleKey))]
		if !ok || s.privilegedExternalAutoRole(ctx, role) {
			continue
		}
		if externalAssertionMappingMatches(assertion, mapping) {
			return role, true, nil
		}
	}
	if role, ok := byKey[strings.ToLower(strings.TrimSpace(policy.DefaultRoleKey))]; ok && !s.privilegedExternalAutoRole(ctx, role) {
		return role, true, nil
	}
	return identitymodel.IdentityRole{}, false, nil
}

func externalAssertionMappingMatches(assertion authmodel.AuthExternalIdentityAssertion, mapping authmodel.AuthExternalRoleMapping) bool {
	claim := strings.ToLower(strings.TrimSpace(mapping.Claim))
	expected := strings.ToLower(strings.TrimSpace(mapping.Match))
	if claim == "" || expected == "" {
		return false
	}
	actual := strings.ToLower(normalizedAssertionClaim(assertion, claim))
	if claim == "email_domain" {
		email := strings.ToLower(strings.TrimSpace(assertion.Email))
		if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
			actual = email[at+1:]
		}
	}
	return actual == expected
}

func normalizedAssertionClaim(assertion authmodel.AuthExternalIdentityAssertion, claim string) string {
	claim = strings.ToLower(strings.TrimSpace(claim))
	switch claim {
	case "provider":
		return normalizeProvider(assertion.Provider)
	case "subject", "provider_subject":
		return strings.TrimSpace(assertion.Subject)
	case "email":
		return strings.TrimSpace(assertion.Email)
	case "phone", "mobile":
		return strings.TrimSpace(assertion.Phone)
	case "display_name", "name":
		return strings.TrimSpace(assertion.DisplayName)
	}
	if assertion.Claims == nil {
		return ""
	}
	return strings.TrimSpace(assertion.Claims[claim])
}

func privilegedExternalAutoRole(role identitymodel.IdentityRole) bool {
	roleKey := strings.ToLower(strings.TrimSpace(valueOrDefault(role.Key, role.ID)))
	return roleKey == "admin" || roleKey == "owner" || strings.Contains(roleKey, "workspace_admin")
}

func (s *AuthDomainService) privilegedExternalAutoRole(ctx context.Context, role identitymodel.IdentityRole) bool {
	if privilegedExternalAutoRole(role) || s.identity == nil {
		return true
	}
	published, ok := s.identity.PublishedRoleDefinition(ctx, valueOrDefault(role.Key, role.ID))
	if !ok {
		return false
	}
	for _, permission := range published.Permissions {
		if strings.TrimSpace(permission) == "workspace.admin" {
			return true
		}
	}
	return false
}
