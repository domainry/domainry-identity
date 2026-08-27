package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

const (
	SystemSeedAdminUserID = "admin"
	SystemSeedAdminLogin  = "admin@example.com"
)

// IssueInitialPassword creates a cryptographically random, one-time credential
// for one new user. Callers must reject an existing user before invoking this
// method and return the plaintext only in the no-store provisioning response.
func (s *AuthDomainService) IssueInitialPassword(ctx context.Context, workspaceID, userID string) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "", badRequest("auth.user_required")
	}
	password, err := s.generateInitialPassword()
	if err != nil {
		return "", err
	}
	if err := s.setPassword(ctx, workspaceID, userID, password, true); err != nil {
		return "", err
	}
	return password, nil
}

func (s *AuthDomainService) EnsureBootstrapCredential(ctx context.Context, workspaceID string) error {
	if s.identityStore == nil {
		return nil
	}
	user, ok, err := s.identity.UserByID(ctx, SystemSeedAdminUserID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return s.ensureSeedCredential(ctx, workspaceID, user.ID)
}

func (s *AuthDomainService) EnsureCredentialsForUsers(ctx context.Context, workspaceID string, users []identitymodel.IdentityUser) error {
	if s.identityStore == nil {
		return nil
	}
	for _, user := range users {
		userID := strings.TrimSpace(user.ID)
		if userID == "" || user.Status == identitymodel.IdentityStatusDisabled {
			continue
		}
		if err := s.ensureSeedCredential(ctx, workspaceID, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuthDomainService) ensureSeedCredential(ctx context.Context, workspaceID, userID string) error {
	_, exists, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.setPassword(ctx, workspaceID, userID, s.defaultPassword, true)
}

func (s *AuthDomainService) Login(ctx context.Context, workspaceID, login, password string) (authmodel.AuthSession, error) {
	return s.LoginForApplication(ctx, workspaceID, login, password, s.audience)
}

func (s *AuthDomainService) LoginForApplication(ctx context.Context, workspaceID, login, password, applicationKey string) (authmodel.AuthSession, error) {
	user, ok, err := s.identity.UserByLogin(ctx, login)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return authmodel.AuthSession{}, forbidden("auth.invalid_credentials")
	}
	credential, ok, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, user.ID)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if !ok {
		return authmodel.AuthSession{}, forbidden("auth.invalid_credentials")
	}
	if credentialLocked(credential, time.Now().UTC()) {
		return authmodel.AuthSession{}, forbidden("auth.account_locked")
	}
	credential, err = s.liftExpiredLock(ctx, workspaceID, credential)
	if err != nil {
		return authmodel.AuthSession{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(password)) != nil {
		if err := s.recordLoginFailure(ctx, workspaceID, credential); err != nil {
			return authmodel.AuthSession{}, err
		}
		return authmodel.AuthSession{}, forbidden("auth.invalid_credentials")
	}
	if err := s.identityStore.RecordIdentityLoginSuccess(ctx, workspaceID, user.ID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return authmodel.AuthSession{}, err
	}
	return s.issueSessionForAudience(ctx, workspaceID, user, applicationKey)
}

func (s *AuthDomainService) ChangePassword(ctx context.Context, workspaceID, userID string, currentPassword string, newPassword string) error {
	userID = strings.TrimSpace(userID)
	currentPassword = strings.TrimSpace(currentPassword)
	newPassword = strings.TrimSpace(newPassword)
	if userID == "" {
		return forbidden("auth.token_required")
	}
	if currentPassword == "" || newPassword == "" {
		return badRequest("auth.password_required")
	}
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}
	credential, ok, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if !ok {
		return forbidden("auth.invalid_credentials")
	}
	if credentialLocked(credential, time.Now().UTC()) {
		return forbidden("auth.account_locked")
	}
	credential, err = s.liftExpiredLock(ctx, workspaceID, credential)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(currentPassword)) != nil {
		if err := s.recordLoginFailure(ctx, workspaceID, credential); err != nil {
			return err
		}
		return forbidden("auth.invalid_credentials")
	}
	return s.setPassword(ctx, workspaceID, userID, newPassword, false)
}

// RequiresPasswordChange reads the authoritative credential handoff state.
// Identities without a password credential (for example external-only
// identities) are not inferred to require a password change.
func (s *AuthDomainService) RequiresPasswordChange(ctx context.Context, workspaceID, userID string) (bool, error) {
	credential, ok, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, strings.TrimSpace(userID))
	if err != nil {
		return false, err
	}
	return ok && credential.MustChangePassword, nil
}

func (s *AuthDomainService) recordLoginFailure(ctx context.Context, workspaceID string, credential identitymodel.IdentityCredential) error {
	now := time.Now().UTC()
	if repository, ok := s.identityStore.(authrepository.AuthLoginAttemptRepository); ok {
		lockedUntil := ""
		if s.maxLoginFailures > 0 {
			lockedUntil = now.Add(s.loginLockDuration).Format(time.RFC3339)
		}
		return repository.RecordIdentityLoginFailure(ctx, workspaceID, credential.UserID, s.maxLoginFailures, lockedUntil, now.Format(time.RFC3339))
	}
	// Compatibility fallback for non-SQL test/project repositories. Production
	// SQL stores implement AuthLoginAttemptRepository and use one atomic UPDATE.
	credential.FailedLoginCount++
	if s.maxLoginFailures > 0 && credential.FailedLoginCount >= s.maxLoginFailures {
		credential.LockedUntil = now.Add(s.loginLockDuration).Format(time.RFC3339)
	}
	return s.identityStore.UpsertIdentityCredential(ctx, workspaceID, credential)
}

// liftExpiredLock clears stale lockout accounting once locked_until has
// passed. Callers invoke it only after credentialLocked reported the lock as
// no longer active. Without this reset an expired lock left
// failed_login_count at the threshold, so a single further bad-password
// attempt instantly re-armed the full lock window and the account stayed
// locked indefinitely until an admin unlock (platform finding #12).
func (s *AuthDomainService) liftExpiredLock(ctx context.Context, workspaceID string, credential identitymodel.IdentityCredential) (identitymodel.IdentityCredential, error) {
	if strings.TrimSpace(credential.LockedUntil) == "" {
		return credential, nil
	}
	credential.FailedLoginCount = 0
	credential.LockedUntil = ""
	if err := s.identityStore.UpsertIdentityCredential(ctx, workspaceID, credential); err != nil {
		return credential, err
	}
	return credential, nil
}

func credentialLocked(credential identitymodel.IdentityCredential, now time.Time) bool {
	lockedUntil := strings.TrimSpace(credential.LockedUntil)
	if lockedUntil == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, lockedUntil)
	if err != nil {
		return false
	}
	return now.Before(parsed)
}

func (s *AuthDomainService) ResetPassword(ctx context.Context, workspaceID, userID string, newPassword string, mustChangePassword bool) error {
	userID = strings.TrimSpace(userID)
	newPassword = strings.TrimSpace(newPassword)
	if userID == "" {
		return badRequest("auth.user_required")
	}
	if newPassword == "" {
		return badRequest("auth.password_required")
	}
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}
	user, ok, err := s.identity.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return forbidden("auth.user_disabled")
	}
	return s.setPassword(ctx, workspaceID, userID, newPassword, mustChangePassword)
}

func (s *AuthDomainService) setPassword(ctx context.Context, workspaceID, userID string, password string, mustChangePassword bool) error {
	if err := s.validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	credential, _, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	credential.UserID = userID
	credential.PasswordHash = string(hash)
	credential.PasswordUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	credential.FailedLoginCount = 0
	credential.LockedUntil = ""
	credential.MustChangePassword = mustChangePassword
	return s.identityStore.UpsertIdentityCredential(ctx, workspaceID, credential)
}

func (s *AuthDomainService) generateInitialPassword() (string, error) {
	random := make([]byte, 18)
	n, err := s.readRandomBytes(random)
	if err != nil {
		return "", fmt.Errorf("generate initial credential: %w", err)
	}
	if n != len(random) {
		return "", fmt.Errorf("generate initial credential: short secure random read: %d/%d", n, len(random))
	}
	// The fixed prefix guarantees every configurable complexity class while the
	// random suffix provides 144 bits of per-user entropy.
	return "Vd!9" + base64.RawURLEncoding.EncodeToString(random), nil
}

func (s *AuthDomainService) validatePassword(password string) error {
	return authpolicy.AuthValidatePassword(s.passwordPolicy, password)
}
