package auth

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
)

// FeishuOffboardingService consumes only verified IdP subjects. The workspace is
// server configuration, never a field supplied by the event or HTTP caller.
type FeishuOffboardingService struct {
	Auth        *AuthApplicationService
	Identity    *identityapplication.IdentityApplicationService
	WorkspaceID string
}

func (s FeishuOffboardingService) Archive(ctx context.Context, unionID string) (string, error) {
	unionID = strings.TrimSpace(unionID)
	if unionID == "" || s.WorkspaceID == "" || s.Auth == nil || s.Identity == nil {
		return "", apperror.New(apperror.KindUnavailable, "auth.feishu_offboarding_unavailable", nil, nil)
	}
	userID, found, err := s.Auth.LinkedExternalIdentityUser(ctx, s.WorkspaceID, "feishu", unionID)
	if err != nil {
		return "", err
	}
	// No automatic invitation, email matching, or account creation on events.
	if !found || userID == "" {
		return "", nil
	}
	_, err = s.Identity.ArchiveDepartedUser(ctx, s.WorkspaceID, userID)
	return userID, err
}
