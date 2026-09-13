package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

const applicationServiceTokenTTL = 5 * time.Minute

func (s *AuthDomainService) IssueApplicationServiceToken(ctx context.Context, workspaceID, applicationKey, audience, credentialID string, grants []authmodel.AuthServiceGrant) (string, time.Time, string, error) {
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, "", err
	}
	workspaceID, applicationKey = strings.TrimSpace(workspaceID), strings.TrimSpace(applicationKey)
	audience, credentialID = strings.TrimSpace(audience), strings.TrimSpace(credentialID)
	if workspaceID == "" || applicationKey == "" || audience == "" || credentialID == "" || len(grants) == 0 {
		return "", time.Time{}, "", forbidden("identity.application_service_exchange_invalid")
	}
	grants = append([]authmodel.AuthServiceGrant(nil), grants...)
	sort.Slice(grants, func(left, right int) bool {
		return grants[left].Resource+"\x00"+grants[left].Action < grants[right].Resource+"\x00"+grants[right].Action
	})
	fingerprint := workspaceID + "\x00" + applicationKey + "\x00" + audience + "\x00" + credentialID
	for _, grant := range grants {
		if strings.TrimSpace(grant.Resource) == "" || strings.TrimSpace(grant.Action) == "" {
			return "", time.Time{}, "", forbidden("identity.application_service_grant_invalid")
		}
		fingerprint += "\x00" + grant.Resource + "\x00" + grant.Action
	}
	revisionDigest := sha256.Sum256([]byte(fingerprint))
	revision := hex.EncodeToString(revisionDigest[:])
	now := time.Now().UTC()
	expiresAt := now.Add(applicationServiceTokenTTL)
	jti, err := s.randomToken()
	if err != nil {
		return "", time.Time{}, "", internalError("generate application service token identifier", err)
	}
	claims := authmodel.AuthClaims{
		Issuer: s.issuer, Audience: audience, Subject: "service:" + applicationKey,
		WorkspaceID: workspaceID, SessionID: "service:" + credentialID,
		AuthorizationRevision: revision, AuthenticationTime: now.Unix(),
		AuthenticationMethods: []string{"application_credential"}, AssuranceLevel: "urn:domainry:acr:service",
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), JTI: jti,
		ServiceApplicationKey: applicationKey, ServiceCredentialID: credentialID, ServiceGrants: grants,
	}
	token, err := s.signClaims(claims)
	return token, expiresAt, revision, err
}

func (s *AuthDomainService) VerifyApplicationServiceToken(ctx context.Context, token, audience, resource, action string) (authmodel.AuthClaims, error) {
	claims, err := s.VerifySignedAccessToken(ctx, token)
	if err != nil {
		return authmodel.AuthClaims{}, err
	}
	if claims.Audience != strings.TrimSpace(audience) || claims.ServiceApplicationKey == "" || claims.ServiceCredentialID == "" || claims.Subject != "service:"+claims.ServiceApplicationKey {
		return authmodel.AuthClaims{}, forbidden("identity.application_service_token_invalid")
	}
	for _, grant := range claims.ServiceGrants {
		if grant.Resource == strings.TrimSpace(resource) && grant.Action == strings.TrimSpace(action) {
			return claims, nil
		}
	}
	return authmodel.AuthClaims{}, forbidden("identity.application_service_grant_denied")
}
