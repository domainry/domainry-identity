package service

import (
	"context"
	"encoding/base32"
	"net/url"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

func (s *AuthDomainService) ManageTOTP(ctx context.Context, workspaceID, userID string, request authmodel.TOTPRequest) (authmodel.TOTPResult, error) {
	ctx = requestcontext.WithWorkspaceID(ctx, workspaceID)
	user, found, err := s.identity.UserByID(ctx, userID)
	if err != nil {
		return authmodel.TOTPResult{}, err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive {
		return authmodel.TOTPResult{}, forbidden("auth.user_disabled")
	}
	repository, ok := s.identityStore.(authrepository.AuthTOTPRepository)
	if !ok {
		return authmodel.TOTPResult{}, badRequest("auth.totp_unavailable")
	}
	state, err := repository.TOTPFactorState(ctx, workspaceID, userID)
	if err != nil {
		return authmodel.TOTPResult{}, err
	}
	switch request.Operation {
	case "status":
		return authmodel.TOTPResult{Enabled: state.Enabled}, nil
	case "enroll", "disable":
		if err := s.verifyTOTPManagementPassword(ctx, workspaceID, userID, request.CurrentPassword); err != nil {
			return authmodel.TOTPResult{}, err
		}
		if request.Operation == "disable" {
			if !state.Enabled {
				return authmodel.TOTPResult{}, nil
			}
			challenge, err := s.beginTOTPChallenge(ctx, workspaceID, userID, "", authmodel.TOTPDisablePurpose, state.Generation, nil)
			if err != nil {
				return authmodel.TOTPResult{}, err
			}
			_, _, err = s.consumeOTPChallenge(ctx, workspaceID, authmodel.TOTPProvider, challenge.State, request.Code, []string{authmodel.TOTPDisablePurpose}, userID)
			return authmodel.TOTPResult{}, err
		}
		if state.Enabled {
			return authmodel.TOTPResult{}, badRequest("auth.totp_already_enabled")
		}
		key := make([]byte, 20)
		if _, err := s.readRandomBytes(key); err != nil {
			return authmodel.TOTPResult{}, internalError("generate TOTP key", err)
		}
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
		challenge, err := s.newTOTPChallenge(workspaceID, userID, "", authmodel.TOTPEnrollmentPurpose, "", nil)
		if err != nil {
			return authmodel.TOTPResult{}, err
		}
		challenge.RequestID = challenge.State
		if err := repository.CreateTOTPEnrollment(ctx, challenge, authmodel.TOTPSecret{Secret: secret}); err != nil {
			return authmodel.TOTPResult{}, err
		}
		issuer := "Domainry"
		if parsed, err := url.Parse(s.issuer); err == nil && parsed.Hostname() != "" {
			issuer = parsed.Hostname()
		}
		account := user.Email
		if strings.TrimSpace(account) == "" {
			account = userID
		}
		// Workspace identity is part of the label, avoiding indistinguishable
		// entries for the same account in several installations/workspaces.
		label := issuer + ":" + workspaceID + "/" + account
		uri := &url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label}
		params := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
		uri.RawQuery = params.Encode()
		return authmodel.TOTPResult{State: challenge.State, SetupKey: secret, OTPAuthURL: uri.String(), ExpiresAt: challenge.ExpiresAt}, nil
	case "confirm":
		_, _, err := s.consumeOTPChallenge(ctx, workspaceID, authmodel.TOTPProvider, request.State, request.Code, []string{authmodel.TOTPEnrollmentPurpose}, userID)
		if err != nil {
			return authmodel.TOTPResult{}, err
		}
		state, err := repository.TOTPFactorState(ctx, workspaceID, userID)
		return authmodel.TOTPResult{Enabled: state.Enabled}, err
	default:
		return authmodel.TOTPResult{}, badRequest("auth.totp_operation_invalid")
	}
}

func (s *AuthDomainService) verifyTOTPManagementPassword(ctx context.Context, workspaceID, userID, password string) error {
	credential, found, err := s.identityStore.GetIdentityCredential(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if !found {
		return forbidden("auth.invalid_credentials")
	}
	if credential.MustChangePassword {
		return forbidden("auth.password_change_required")
	}
	if credentialLocked(credential, time.Now().UTC()) {
		return forbidden("auth.account_locked")
	}
	credential, err = s.liftExpiredLock(ctx, workspaceID, credential)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(password)) != nil {
		if err := s.recordLoginFailure(ctx, workspaceID, credential); err != nil {
			return err
		}
		return forbidden("auth.invalid_credentials")
	}
	return s.identityStore.RecordIdentityLoginSuccess(ctx, workspaceID, userID, time.Now().UTC().Format(time.RFC3339))
}

func (s *AuthDomainService) newTOTPChallenge(workspaceID, userID, applicationKey, purpose, generation string, methods []string) (authmodel.AuthProviderChallenge, error) {
	state, err := s.randomToken()
	if err != nil {
		return authmodel.AuthProviderChallenge{}, err
	}
	now := time.Now().UTC()
	return authmodel.AuthProviderChallenge{WorkspaceID: workspaceID, UserID: userID, ApplicationKey: applicationKey,
		Provider: authmodel.TOTPProvider, Type: "totp", Purpose: purpose, Status: authmodel.AuthChallengeStatusActive,
		State: state, RequestID: generation, AuthenticationMethods: methods, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339)}, nil
}

func (s *AuthDomainService) beginTOTPChallenge(ctx context.Context, workspaceID, userID, applicationKey, purpose, generation string, methods []string) (authprojection.AuthProviderStartResponse, error) {
	repository, ok := s.identityStore.(authrepository.AuthLoginTransactionRepository)
	if !ok {
		return authprojection.AuthProviderStartResponse{}, badRequest("auth.totp_unavailable")
	}
	challenge, err := s.newTOTPChallenge(workspaceID, userID, applicationKey, purpose, generation, methods)
	if err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	if err := repository.CreateAuthLoginTransaction(ctx, challenge); err != nil {
		return authprojection.AuthProviderStartResponse{}, err
	}
	return authprojection.AuthProviderStartResponse{Provider: challenge.Provider, State: challenge.State, Type: challenge.Type, Purpose: challenge.Purpose, Status: challenge.Status, ExpiresAt: challenge.ExpiresAt}, nil
}

func (s *AuthDomainService) totpState(ctx context.Context, workspaceID, userID string) (authmodel.TOTPFactorState, error) {
	if repository, ok := s.identityStore.(authrepository.AuthTOTPRepository); ok {
		return repository.TOTPFactorState(ctx, workspaceID, userID)
	}
	return authmodel.TOTPFactorState{}, nil
}
