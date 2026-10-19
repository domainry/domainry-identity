package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-identity/credentialemail"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

const EmailCredentialProvider = "email_credential"
const PasswordSetupPurpose = "password_setup"
const PasswordRecoveryPurpose = "password_recovery"

func (s *AuthDomainService) ConfigureCredentialEmail(delivery credentialemail.Delivery, setupURL string) error {
	if setupURL != "" {
		u, err := url.Parse(setupURL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
			return fmt.Errorf("credential setup URL must be a fixed HTTPS product URL (HTTP is allowed only on loopback)")
		}
	}
	s.credentialEmail, s.credentialSetupURL = delivery, setupURL
	return nil
}

func emailCredentialUnavailable() error {
	return apperror.New(apperror.KindUnavailable, "auth.credential_email_unavailable", nil, nil)
}

func (s *AuthDomainService) CheckCredentialEmail(ctx context.Context, workspace string) error {
	if s.credentialEmail == nil || s.credentialSetupURL == "" {
		return emailCredentialUnavailable()
	}
	if err := s.credentialEmail.Ready(ctx, workspace); err != nil {
		return emailCredentialUnavailable()
	}
	return nil
}

func (s *AuthDomainService) SendPasswordInvitation(ctx context.Context, workspace, userID string) (credentialemail.Receipt, error) {
	if err := s.CheckCredentialEmail(ctx, workspace); err != nil {
		return credentialemail.Receipt{}, err
	}
	user, found, err := s.identity.UserByID(ctx, strings.TrimSpace(userID))
	if err != nil {
		return credentialemail.Receipt{}, err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive || user.AccountType != identitymodel.IdentityAccountHuman {
		return credentialemail.Receipt{}, forbidden("auth.user_disabled")
	}
	challenge, err := s.beginEmailCredential(ctx, workspace, user, user.Email, PasswordSetupPurpose)
	if err != nil {
		return credentialemail.Receipt{}, err
	}
	u, _ := url.Parse(s.credentialSetupURL)
	u.Fragment = url.Values{"token": {challenge.State}, "workspace": {workspace}}.Encode()
	text := "你已受邀加入工作区。请打开以下链接设置自己的登录密码：\n\n" + u.String() + "\n\n链接仅可使用一次，30 分钟后失效。若非本人操作，请忽略此邮件。"
	if err := s.deliverEmailCredential(ctx, challenge, "工作区邀请 · 设置登录密码", text); err != nil {
		return credentialemail.Receipt{}, err
	}
	return credentialemail.Receipt{Status: "sent", ExpiresAt: challenge.ExpiresAt}, nil
}

func (s *AuthDomainService) StartPasswordRecovery(ctx context.Context, workspace, email string) (credentialemail.Challenge, error) {
	if err := s.CheckCredentialEmail(ctx, workspace); err != nil {
		return credentialemail.Challenge{}, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return credentialemail.Challenge{}, badRequest("auth.recovery_email_required")
	}
	user, found, err := s.identity.UserByLogin(ctx, email)
	if err != nil {
		return credentialemail.Challenge{}, err
	}
	valid := found && user.Status == identitymodel.IdentityStatusActive && user.AccountType == identitymodel.IdentityAccountHuman && strings.EqualFold(user.Email, email)
	if !valid {
		user = identitymodel.IdentityUser{}
	}
	challenge, err := s.beginEmailCredential(ctx, workspace, user, email, PasswordRecoveryPurpose)
	if err != nil {
		return credentialemail.Challenge{}, err
	}
	if valid {
		text := "你正在找回工作区登录密码。\n\n验证码：" + challenge.Code + "\n\n验证码 10 分钟内有效，仅可使用一次。若非本人操作，请忽略此邮件。"
		// A provider outage must not turn this anonymous endpoint into an account
		// existence probe. Delivery marks failed grants unusable; the public reply
		// remains identical to the unknown-email case.
		_ = s.deliverEmailCredential(ctx, challenge, "工作区密码找回验证码", text)
	}
	return credentialemail.Challenge{State: challenge.State, ExpiresAt: challenge.ExpiresAt, RetryAt: challenge.RetryAt}, nil
}

func (s *AuthDomainService) beginEmailCredential(ctx context.Context, workspace string, user identitymodel.IdentityUser, email, purpose string) (authmodel.AuthProviderChallenge, error) {
	repository, ok := s.identityStore.(authrepository.AuthOTPTransactionRepository)
	if !ok {
		return authmodel.AuthProviderChallenge{}, emailCredentialUnavailable()
	}
	state, err := s.randomToken()
	if err != nil {
		return authmodel.AuthProviderChallenge{}, err
	}
	now, lifetime := time.Now().UTC(), 30*time.Minute
	code := ""
	if purpose == PasswordRecoveryPurpose {
		lifetime = 10 * time.Minute
		code, err = s.randomDigits(6)
		if err != nil {
			return authmodel.AuthProviderChallenge{}, err
		}
	}
	marker := ""
	if user.ID != "" {
		credential, found, readErr := s.identityStore.GetIdentityCredential(ctx, workspace, user.ID)
		if readErr != nil {
			return authmodel.AuthProviderChallenge{}, readErr
		}
		if found {
			digest := sha256.Sum256([]byte(credential.PasswordHash))
			marker = hex.EncodeToString(digest[:])
		}
	}
	challenge := authmodel.AuthProviderChallenge{WorkspaceID: workspace, Provider: EmailCredentialProvider, Purpose: purpose, Type: "email_credential", Status: authmodel.AuthChallengeStatusActive, UserID: user.ID, Email: strings.ToLower(strings.TrimSpace(email)), State: state, Code: code, Nonce: marker, CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(lifetime).Format(time.RFC3339Nano), RetryAt: now.Add(s.otpResendCooldown).Format(time.RFC3339Nano)}
	created, err := repository.CreateAuthOTPTransaction(ctx, challenge, s.otpDeliveryKey(workspace, EmailCredentialProvider, purpose+":"+challenge.Email), now.Add(s.otpResendCooldown), now)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, err
	}
	if !created {
		return authmodel.AuthProviderChallenge{}, forbidden("auth.otp_rate_limited")
	}
	return challenge, nil
}

func (s *AuthDomainService) deliverEmailCredential(ctx context.Context, challenge authmodel.AuthProviderChallenge, subject, text string) error {
	digest := sha256.Sum256([]byte(challenge.State))
	err := s.credentialEmail.Send(ctx, credentialemail.Message{ID: "credential-email-" + hex.EncodeToString(digest[:]), WorkspaceID: challenge.WorkspaceID, To: challenge.Email, Subject: subject, Text: text, ExpiresAt: challenge.ExpiresAt})
	if err == nil {
		return nil
	}
	if statusErr := s.UpdateOTPChallengeDelivery(ctx, challenge.WorkspaceID, challenge.Provider, challenge.State, authmodel.AuthChallengeStatusFailed, "", "credential_email_delivery_failed"); statusErr != nil {
		return statusErr
	}
	return apperror.New(apperror.KindUnavailable, "auth.credential_email_delivery_failed", nil, nil)
}

func (s *AuthDomainService) CompleteEmailPassword(ctx context.Context, workspace, state, purpose, code, password string) error {
	if purpose != PasswordSetupPurpose && purpose != PasswordRecoveryPurpose {
		return forbidden("auth.credential_grant_invalid")
	}
	if len(state) < 20 || len(state) > 256 {
		return forbidden("auth.credential_grant_invalid")
	}
	if err := s.validatePassword(password); err != nil {
		return err
	}
	repository, ok := s.identityStore.(authrepository.AuthEmailCredentialRepository)
	if !ok {
		return emailCredentialUnavailable()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, accepted, err := repository.CompleteEmailCredential(ctx, workspace, state, purpose, code, string(hash), s.otpMaxAttempts, time.Now().UTC())
	if err != nil {
		return err
	}
	if !accepted {
		return forbidden("auth.credential_grant_invalid")
	}
	return nil
}
