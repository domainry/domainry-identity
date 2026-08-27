package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"strings"
	"time"

	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) Refresh(ctx context.Context, workspaceID, refreshToken string) (authmodel.AuthSession, error) {
	return s.RefreshForApplication(ctx, workspaceID, refreshToken, "")
}

// RefreshForApplication rotates a refresh credential only when it belongs to
// the Runtime application that presented it. The check happens before the
// atomic rotation, so a credential from another audience cannot be consumed as
// a side effect of a rejected request.
func (s *AuthDomainService) RefreshForApplication(ctx context.Context, workspaceID, refreshToken, applicationKey string) (authmodel.AuthSession, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	applicationKey = strings.TrimSpace(applicationKey)
	if refreshToken == "" {
		return authmodel.AuthSession{}, forbidden("auth.session_expired")
	}
	currentHash := hashRefreshToken(refreshToken)
	session, ok, err := s.identityStore.GetAuthRefreshTokenByHash(ctx, workspaceID, currentHash)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !ok || tokenExpired(session.ExpiresAt) {
		return authmodel.AuthSession{}, forbidden("auth.session_expired")
	}
	if applicationKey != "" && strings.TrimSpace(session.Audience) != applicationKey {
		return authmodel.AuthSession{}, forbidden("identity.application_mismatch")
	}
	if strings.TrimSpace(session.RevokedAt) != "" {
		if strings.TrimSpace(session.ReplacedByID) != "" {
			_, _ = s.identityStore.RevokeAuthRefreshTokensForUser(ctx, workspaceID, session.UserID, time.Now().UTC().Format(time.RFC3339))
			return authmodel.AuthSession{}, forbidden("auth.refresh_token_reused")
		}
		return authmodel.AuthSession{}, forbidden("auth.session_expired")
	}
	user, ok, err := s.identity.UserByID(ctx, session.UserID)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return authmodel.AuthSession{}, forbidden("auth.user_disabled")
	}
	result, replacement, err := s.prepareSessionForAudienceWithID(ctx, workspaceID, user, session.SessionID, session.Audience)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	rotator, ok := s.identityStore.(authrepository.AuthRefreshRotationRepository)
	if !ok {
		return authmodel.AuthSession{}, internalError("atomic refresh token rotation is unavailable", nil)
	}
	rotated, err := rotator.RotateAuthRefreshToken(ctx, workspaceID, session.ID, time.Now().UTC().Format(time.RFC3339), replacement)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !rotated {
		return authmodel.AuthSession{}, forbidden("auth.session_expired")
	}
	return result, nil
}

func (s *AuthDomainService) Logout(ctx context.Context, workspaceID, refreshToken string) {
	_ = s.LogoutForApplication(ctx, workspaceID, refreshToken, "")
}

// LogoutForApplication refuses to revoke a session owned by another Runtime
// application. Legacy callers can continue to use Logout without an expected
// audience while SDK/SaaS paths always provide one.
func (s *AuthDomainService) LogoutForApplication(ctx context.Context, workspaceID, refreshToken, applicationKey string) error {
	refreshToken = strings.TrimSpace(refreshToken)
	applicationKey = strings.TrimSpace(applicationKey)
	if refreshToken == "" {
		return nil
	}
	session, ok, err := s.identityStore.GetAuthRefreshTokenByHash(ctx, workspaceID, hashRefreshToken(refreshToken))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if applicationKey != "" && strings.TrimSpace(session.Audience) != applicationKey {
		return forbidden("identity.application_mismatch")
	}
	if sessions, ok := s.identityStore.(authrepository.AuthSessionRepository); ok {
		_, err = sessions.RevokeAuthSession(ctx, workspaceID, session.UserID, session.SessionID, time.Now().UTC().Format(time.RFC3339))
		return err
	}
	return s.identityStore.RevokeAuthRefreshToken(ctx, workspaceID, session.ID, time.Now().UTC().Format(time.RFC3339), "")
}
