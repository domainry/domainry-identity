package identitysdkadapter

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

type sdkApplicationServiceVerifier struct{ binding *sdkBinding }

func (adapter sdkApplicationServiceVerifier) Verify(ctx context.Context, request identitysdk.VerifyApplicationServiceTokenRequest) (identitysdk.ApplicationServicePrincipal, error) {
	if adapter.binding == nil {
		return identitysdk.ApplicationServicePrincipal{}, fmt.Errorf("Identity application service verifier is unavailable")
	}
	return adapter.binding.VerifyApplicationServiceToken(ctx, request)
}

// IssueApplicationServiceToken is consumed by Identity's authenticated remote
// transport and by trusted same-process infrastructure after the registered
// source application and exact credential rotation have both been validated.
func (binding *sdkBinding) IssueApplicationServiceToken(ctx context.Context, request identitysdk.ExchangeApplicationServiceTokenRequest, credentialID string) (identitysdk.ApplicationServiceToken, error) {
	if binding == nil || binding.auth == nil || !request.Application.TenantID.Valid() || !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() || !request.Audience.Valid() || strings.TrimSpace(credentialID) == "" || len(request.Grants) == 0 {
		return identitysdk.ApplicationServiceToken{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.application_service_exchange_invalid"}
	}
	registered, err := binding.applicationRegistered(ctx, identitysdk.ApplicationRef{TenantID: request.Application.TenantID, WorkspaceID: request.Application.WorkspaceID, ApplicationKey: request.Application.ApplicationKey})
	if err != nil {
		return identitysdk.ApplicationServiceToken{}, sdkBoundaryError(err)
	}
	if !registered {
		return identitysdk.ApplicationServiceToken{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.application_service_source_not_registered"}
	}
	registered, err = binding.applicationRegistered(ctx, identitysdk.ApplicationRef{TenantID: request.Application.TenantID, WorkspaceID: request.Application.WorkspaceID, ApplicationKey: request.Audience})
	if err != nil {
		return identitysdk.ApplicationServiceToken{}, sdkBoundaryError(err)
	}
	if !registered {
		return identitysdk.ApplicationServiceToken{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.application_service_audience_not_registered"}
	}
	grants := make([]authmodel.AuthServiceGrant, 0, len(request.Grants))
	seen := map[string]struct{}{}
	for _, grant := range request.Grants {
		key := string(grant.Resource) + "\x00" + string(grant.Action)
		if !grant.Valid() {
			return identitysdk.ApplicationServiceToken{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.application_service_grant_invalid"}
		}
		if _, duplicate := seen[key]; duplicate {
			return identitysdk.ApplicationServiceToken{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.application_service_grant_duplicate"}
		}
		seen[key] = struct{}{}
		grants = append(grants, authmodel.AuthServiceGrant{Resource: string(grant.Resource), Action: string(grant.Action)})
	}
	accessToken, expiresAt, _, err := binding.auth.IssueApplicationServiceToken(ctx, string(request.Application.TenantID), string(request.Application.WorkspaceID), string(request.Application.ApplicationKey), string(request.Audience), credentialID, grants)
	if err != nil {
		return identitysdk.ApplicationServiceToken{}, sdkBoundaryError(err)
	}
	return identitysdk.ApplicationServiceToken{
		AccessToken: accessToken, TokenType: "Bearer", ExpiresAt: expiresAt,
		Application: request.Application, Audience: request.Audience, CredentialID: credentialID,
		Grants: append([]identitysdk.ApplicationServiceGrant(nil), request.Grants...),
	}, nil
}

func (binding *sdkBinding) VerifyApplicationServiceToken(ctx context.Context, request identitysdk.VerifyApplicationServiceTokenRequest) (identitysdk.ApplicationServicePrincipal, error) {
	if binding == nil || binding.auth == nil || strings.TrimSpace(request.AccessToken) == "" || !request.Audience.Valid() || !request.Grant.Valid() {
		return identitysdk.ApplicationServicePrincipal{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.application_service_verify_invalid"}
	}
	claims, err := binding.auth.VerifyApplicationServiceToken(ctx, request.AccessToken, string(request.Audience), string(request.Grant.Resource), string(request.Grant.Action))
	if err != nil {
		return identitysdk.ApplicationServicePrincipal{}, sdkBoundaryError(err)
	}
	return identitysdk.ApplicationServicePrincipal{
		SubjectID:   identitysdk.SubjectID(claims.Subject),
		Application: identitysdk.ApplicationRef{TenantID: identitysdk.TenantID(claims.TenantID), WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), ApplicationKey: identitysdk.ApplicationKey(claims.ServiceApplicationKey)},
		Audience:    request.Audience, CredentialID: claims.ServiceCredentialID,
		AuthorizationRevision: identitysdk.AuthorizationRevision(claims.AuthorizationRevision), ExpiresAt: timeFromUnix(claims.ExpiresAt),
	}, nil
}

func timeFromUnix(value int64) time.Time { return time.Unix(value, 0).UTC() }

var _ interface {
	IssueApplicationServiceToken(context.Context, identitysdk.ExchangeApplicationServiceTokenRequest, string) (identitysdk.ApplicationServiceToken, error)
	VerifyApplicationServiceToken(context.Context, identitysdk.VerifyApplicationServiceTokenRequest) (identitysdk.ApplicationServicePrincipal, error)
} = (*sdkBinding)(nil)

var _ identitysdk.ApplicationServiceVerificationBinding = (*sdkBinding)(nil)
var _ identitysdk.ApplicationServiceTokenVerifier = sdkApplicationServiceVerifier{}
