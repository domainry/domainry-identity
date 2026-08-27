package service

import (
	"context"
	"strings"
	"time"

	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type UserSecurityProfile struct {
	Credential       *UserCredentialSecuritySummary   `json:"credential,omitempty"`
	Sessions         []UserSessionSecuritySummary     `json:"sessions"`
	ExternalAccounts []ExternalAccountSecuritySummary `json:"external_accounts"`
	MFAFactors       []MFAFactorSecuritySummary       `json:"mfa_factors"`
	MFAEnabled       bool                             `json:"mfa_enabled"`
	ActiveSessions   int                              `json:"active_sessions"`
	Locked           bool                             `json:"locked"`
}

type UserCredentialSecuritySummary struct {
	UserID             string `json:"user_id"`
	PasswordUpdatedAt  string `json:"password_updated_at,omitempty"`
	FailedLoginCount   int    `json:"failed_login_count"`
	LockedUntil        string `json:"locked_until,omitempty"`
	LastLoginAt        string `json:"last_login_at,omitempty"`
	MustChangePassword bool   `json:"must_change_password"`
}

type UserSessionSecuritySummary struct {
	ID         string `json:"id"`
	SessionID  string `json:"session_id"`
	ExpiresAt  string `json:"expires_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

type ExternalAccountSecuritySummary struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	LinkedAt    string `json:"linked_at,omitempty"`
}

type MFAFactorSecuritySummary struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Label      string `json:"label,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Status     string `json:"status"`
	VerifiedAt string `json:"verified_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

func (s *AuthDomainService) UserSecurityProfile(ctx context.Context, workspaceID, userID string) (UserSecurityProfile, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return UserSecurityProfile{}, badRequest("auth.user_required")
	}
	if _, ok, err := s.identity.UserByID(ctx, userID); err != nil {
		return UserSecurityProfile{}, err
	} else if !ok {
		return UserSecurityProfile{}, badRequest("backend.identity.user_not_found", "user", userID)
	}
	profile := UserSecurityProfile{
		Sessions:         []UserSessionSecuritySummary{},
		ExternalAccounts: []ExternalAccountSecuritySummary{},
		MFAFactors:       []MFAFactorSecuritySummary{},
	}
	if credential, ok, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID); err != nil {
		return profile, err
	} else if ok {
		profile.Credential = &UserCredentialSecuritySummary{
			UserID: credential.UserID, PasswordUpdatedAt: credential.PasswordUpdatedAt,
			FailedLoginCount: credential.FailedLoginCount, LockedUntil: credential.LockedUntil,
			LastLoginAt: credential.LastLoginAt, MustChangePassword: credential.MustChangePassword,
		}
		profile.Locked = credentialLocked(credential, time.Now())
	}
	sessions, err := s.identityStore.ListAuthRefreshTokensForUser(ctx, workspaceID, userID)
	if err != nil {
		return profile, err
	}
	now := time.Now().UTC()
	for _, session := range sessions {
		profile.Sessions = append(profile.Sessions, UserSessionSecuritySummary{
			ID: session.ID, SessionID: session.SessionID, ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt, CreatedAt: session.CreatedAt, LastUsedAt: session.LastUsedAt,
		})
		if session.RevokedAt == "" && tokenExpiresAfter(session.ExpiresAt, now) {
			profile.ActiveSessions++
		}
	}
	accounts, err := s.identityStore.ListIdentityExternalAccounts(ctx, workspaceID, userID)
	if err != nil {
		return profile, err
	}
	for _, account := range accounts {
		profile.ExternalAccounts = append(profile.ExternalAccounts, ExternalAccountSecuritySummary{
			ID: account.ID, Provider: account.Provider, Email: account.Email, Phone: account.Phone,
			DisplayName: account.DisplayName, LinkedAt: account.LinkedAt,
		})
	}
	if repository, ok := s.identityStore.(authrepository.AuthMFARepository); ok {
		factors, err := repository.ListIdentityMFAFactors(ctx, workspaceID, userID)
		if err != nil {
			return profile, err
		}
		for _, factor := range factors {
			profile.MFAFactors = append(profile.MFAFactors, MFAFactorSecuritySummary{
				ID: factor.ID, Type: factor.Type, Label: factor.Label, Provider: factor.Provider,
				Status: factor.Status, VerifiedAt: factor.VerifiedAt, LastUsedAt: factor.LastUsedAt,
				CreatedAt: factor.CreatedAt,
			})
			if factor.Status == "active" && factor.VerifiedAt != "" {
				profile.MFAEnabled = true
			}
		}
	}
	return profile, nil
}

// RegisterVerifiedMFAFactor accepts only provider-verified factor metadata.
// TOTP/WebAuthn secrets and challenge verification stay inside the configured
// authentication provider rather than crossing into Runtime persistence.
func (s *AuthDomainService) RegisterVerifiedMFAFactor(ctx context.Context, workspaceID, userID string, factor identitymodel.IdentityMFAFactor) error {
	userID = strings.TrimSpace(userID)
	factor.ID, factor.Type = strings.TrimSpace(factor.ID), strings.TrimSpace(factor.Type)
	factor.VerifiedAt = strings.TrimSpace(factor.VerifiedAt)
	if userID == "" {
		return badRequest("auth.user_required")
	}
	if factor.ID == "" {
		return badRequest("auth.mfa_factor_id_required")
	}
	switch factor.Type {
	case "totp", "webauthn", "recovery", "external":
	default:
		return badRequest("auth.mfa_factor_type_invalid")
	}
	if factor.VerifiedAt == "" {
		return badRequest("auth.mfa_factor_not_verified")
	}
	user, ok, err := s.identity.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return badRequest("backend.identity.user_not_found", "user", userID)
	}
	if user.Status != identitymodel.IdentityStatusActive {
		return badRequest("auth.user_inactive")
	}
	repository, ok := s.identityStore.(authrepository.AuthMFARepository)
	if !ok {
		return badRequest("auth.mfa_unavailable")
	}
	factor.UserID, factor.Status = userID, "active"
	return repository.UpsertIdentityMFAFactor(ctx, workspaceID, factor)
}

func (s *AuthDomainService) RevokeMFAFactor(ctx context.Context, workspaceID, userID, factorID string) error {
	userID, factorID = strings.TrimSpace(userID), strings.TrimSpace(factorID)
	if userID == "" {
		return badRequest("auth.user_required")
	}
	if factorID == "" {
		return badRequest("auth.mfa_factor_id_required")
	}
	if _, ok, err := s.identity.UserByID(ctx, userID); err != nil {
		return err
	} else if !ok {
		return badRequest("backend.identity.user_not_found", "user", userID)
	}
	repository, ok := s.identityStore.(authrepository.AuthMFARepository)
	if !ok {
		return badRequest("auth.mfa_unavailable")
	}
	return repository.RevokeIdentityMFAFactor(ctx, workspaceID, userID, factorID)
}

func (s *AuthDomainService) UnlockUser(ctx context.Context, workspaceID, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return badRequest("auth.user_required")
	}
	credential, ok, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if !ok {
		return badRequest("auth.credential_missing")
	}
	credential.FailedLoginCount = 0
	credential.LockedUntil = ""
	return s.identityStore.UpsertIdentityCredential(ctx, workspaceID, credential)
}

func (s *AuthDomainService) ForceLogoutUser(ctx context.Context, workspaceID, userID string) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, badRequest("auth.user_required")
	}
	if _, ok, err := s.identity.UserByID(ctx, userID); err != nil {
		return 0, err
	} else if !ok {
		return 0, badRequest("backend.identity.user_not_found", "user", userID)
	}
	return s.identityStore.RevokeAuthRefreshTokensForUser(ctx, workspaceID, userID, time.Now().UTC().Format(time.RFC3339))
}

type RevokeOtherSessionsResult struct {
	RevokedSessions  int    `json:"revoked_sessions"`
	CurrentSessionID string `json:"current_session_id"`
}

func (s *AuthDomainService) RevokeOtherSessions(ctx context.Context, accessToken string) (RevokeOtherSessionsResult, error) {
	claims, err := s.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return RevokeOtherSessionsResult{}, err
	}
	sessions, ok := s.identityStore.(authrepository.AuthSessionRepository)
	if !ok {
		return RevokeOtherSessionsResult{}, forbidden("auth.session_expired")
	}
	count, err := sessions.RevokeOtherAuthSessions(ctx, claims.WorkspaceID, claims.Subject, claims.SessionID, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return RevokeOtherSessionsResult{}, err
	}
	return RevokeOtherSessionsResult{RevokedSessions: count, CurrentSessionID: claims.SessionID}, nil
}

func tokenExpiresAfter(value string, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return true
	}
	return expiresAt.After(now)
}
