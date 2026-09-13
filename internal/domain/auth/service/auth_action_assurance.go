package service

import (
	"context"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const actionAssuranceAudience = "domainry-action-assurance"

func (s *AuthDomainService) IssueActionAssuranceReceipt(ctx context.Context, challenge authmodel.AuthProviderChallenge) (authmodel.AuthActionAssuranceReceipt, error) {
	if err := ctx.Err(); err != nil {
		return authmodel.AuthActionAssuranceReceipt{}, err
	}
	if strings.TrimSpace(challenge.WorkspaceID) == "" || strings.TrimSpace(challenge.UserID) == "" || strings.TrimSpace(challenge.State) == "" || challenge.Purpose != authmodel.AuthChallengePurposeAction || challenge.Status != authmodel.AuthChallengeStatusConsumed {
		return authmodel.AuthActionAssuranceReceipt{}, forbidden("auth.action_assurance_challenge_invalid")
	}
	now := time.Now().UTC()
	expiresAt := now.Add(2 * time.Minute)
	methods := []string{"otp"}
	token, err := s.signClaims(authmodel.AuthClaims{
		Audience: actionAssuranceAudience, Subject: challenge.UserID, WorkspaceID: challenge.WorkspaceID,
		SessionID: challenge.State, AuthenticationTime: now.Unix(), AuthenticationMethods: methods, AssuranceLevel: "urn:domainry:acr:2",
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), TokenPurpose: authmodel.AuthChallengePurposeAction,
	})
	if err != nil {
		return authmodel.AuthActionAssuranceReceipt{}, err
	}
	return authmodel.AuthActionAssuranceReceipt{Token: token, WorkspaceID: challenge.WorkspaceID, UserID: challenge.UserID, Methods: methods, ExpiresAt: expiresAt.Format(time.RFC3339)}, nil

}

func (s *AuthDomainService) ValidateActionAssuranceReceipt(ctx context.Context, token, workspaceID, userID string) (authmodel.AuthActionAssuranceReceipt, error) {
	claims, err := s.VerifySignedAccessToken(ctx, token)
	if err != nil {
		return authmodel.AuthActionAssuranceReceipt{}, err
	}
	workspaceID, userID = strings.TrimSpace(workspaceID), strings.TrimSpace(userID)
	if claims.TokenPurpose != authmodel.AuthChallengePurposeAction || claims.Audience != actionAssuranceAudience || claims.WorkspaceID != workspaceID || claims.Subject != userID || claims.AssuranceLevel != "urn:domainry:acr:2" || !authMethodPresent(claims.AuthenticationMethods, "otp") {
		return authmodel.AuthActionAssuranceReceipt{}, forbidden("auth.action_assurance_receipt_invalid")
	}
	return authmodel.AuthActionAssuranceReceipt{Token: token, WorkspaceID: claims.WorkspaceID, UserID: claims.Subject, Methods: append([]string(nil), claims.AuthenticationMethods...), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339)}, nil
}

func authMethodPresent(methods []string, expected string) bool {
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), expected) {
			return true
		}
	}
	return false
}
