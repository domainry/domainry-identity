package identity

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityUserProvisioningResponse struct {
	identitymodel.IdentityUser
	InitialPassword    string `json:"initial_password"`
	MustChangePassword bool   `json:"must_change_password"`
}

func (h *IdentityHandler) listIdentityUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.ListUsers(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, users)
}

func (h *IdentityHandler) searchIdentityUsers(w http.ResponseWriter, r *http.Request) {
	page, err := h.users.SearchUsers(r.Context(), identityListQuery(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, page)
}

func (h *IdentityHandler) searchIdentityUserDirectory(w http.ResponseWriter, r *http.Request) {
	if batch, ok := h.userSecurity.(IdentityUserSecurityBatch); ok {
		page, err := h.users.SearchUserDirectoryBatch(r.Context(), identityListQuery(r), func(ctx context.Context, workspaceID string, userIDs []string) (map[string]identityapplication.IdentityUserDirectorySecuritySummary, error) {
			profiles, readErr := batch.UserDirectorySecurityProfiles(ctx, workspaceID, userIDs)
			if readErr != nil {
				return nil, readErr
			}
			summaries := make(map[string]identityapplication.IdentityUserDirectorySecuritySummary, len(profiles))
			for userID, profile := range profiles {
				lastLoginAt := ""
				if profile.Credential != nil {
					lastLoginAt = profile.Credential.LastLoginAt
				}
				summaries[userID] = identityapplication.IdentityUserDirectorySecuritySummary{
					MFAEnabled: profile.MFAEnabled, Locked: profile.Locked, ActiveSessions: profile.ActiveSessions, LastLoginAt: lastLoginAt,
				}
			}
			return summaries, nil
		})
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		h.writeJSON(w, http.StatusOK, page)
		return
	}
	page, err := h.users.SearchUserDirectory(r.Context(), identityListQuery(r), func(ctx context.Context, workspaceID, userID string) (identityapplication.IdentityUserDirectorySecuritySummary, error) {
		profile, readErr := h.userSecurity.UserSecurityProfile(ctx, workspaceID, userID)
		if readErr != nil {
			return identityapplication.IdentityUserDirectorySecuritySummary{}, readErr
		}
		lastLoginAt := ""
		if profile.Credential != nil {
			lastLoginAt = profile.Credential.LastLoginAt
		}
		return identityapplication.IdentityUserDirectorySecuritySummary{
			MFAEnabled: profile.MFAEnabled, Locked: profile.Locked,
			ActiveSessions: profile.ActiveSessions, LastLoginAt: lastLoginAt,
		}, nil
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, page)
}

func (h *IdentityHandler) getIdentityUser(w http.ResponseWriter, r *http.Request) {
	user, found, err := h.users.UserByID(r.Context(), strings.TrimSpace(r.PathValue("userID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.user_not_found")
		return
	}
	h.writeIdentityAuthoringResource(w, r, "identity.user", user.ID, user)
}

func (h *IdentityHandler) createIdentityUser(w http.ResponseWriter, r *http.Request) {
	var user identitymodel.IdentityUser
	if !h.decodeJSON(w, r, &user) {
		return
	}
	user.ID = strings.TrimSpace(user.ID)
	if _, found, err := h.users.UserByID(r.Context(), user.ID); err != nil {
		h.writeServiceError(w, r, err)
		return
	} else if found {
		h.writeServiceError(w, r, apperror.New(
			apperror.KindConflict,
			"backend.identity.user_already_exists",
			nil,
			map[string]string{"user": user.ID},
		))
		return
	}
	if err := h.users.UpsertUser(r.Context(), user); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	persisted, found, err := h.users.UserByID(r.Context(), user.ID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusInternalServerError, "backend.identity.user_not_found")
		return
	}
	if h.userSecurity == nil {
		_ = h.users.RemoveUser(r.Context(), user.ID)
		h.writeServiceError(w, r, apperror.New(
			apperror.KindInternal,
			"backend.identity.initial_credential_issuer_unavailable",
			nil,
			map[string]string{"user": user.ID},
		))
		return
	}
	initialPassword, err := h.userSecurity.IssueInitialPassword(
		r.Context(),
		h.principal(r).WorkspaceID,
		user.ID,
	)
	if err != nil {
		_ = h.users.RemoveUser(r.Context(), user.ID)
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_created", "identity_user", user.ID, "Created identity user", map[string]any{"email": user.Email, "status": user.Status})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	h.writeJSON(w, http.StatusCreated, identityUserProvisioningResponse{
		IdentityUser:       persisted,
		InitialPassword:    initialPassword,
		MustChangePassword: true,
	})
}

func (h *IdentityHandler) updateIdentityUser(w http.ResponseWriter, r *http.Request) {
	var user identitymodel.IdentityUser
	if !h.decodeJSON(w, r, &user) {
		return
	}
	user.ID = valueOrDefault(strings.TrimSpace(r.PathValue("userID")), user.ID)
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.user", user.ID, r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), user, principal,
		func(ctx context.Context) (any, bool, error) { return h.users.UserByID(ctx, user.ID) },
		func(ctx context.Context) (any, error) {
			if executeErr := h.users.UpsertUser(ctx, user); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_user_updated", "identity_user", user.ID, "Updated identity user", map[string]any{"email": user.Email, "status": user.Status})
			persisted, found, readErr := h.users.UserByID(ctx, user.ID)
			if readErr != nil {
				return nil, readErr
			}
			if !found {
				return nil, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.user_not_found"}
			}
			return persisted, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}

func (h *IdentityHandler) deleteIdentityUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	if err := h.users.RemoveUser(r.Context(), userID); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_deleted", "identity_user", userID, "Deleted identity user", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdentityHandler) getIdentityUserDeletionImpact(w http.ResponseWriter, r *http.Request) {
	impact, err := h.users.UserDeletionImpact(r.Context(), strings.TrimSpace(r.PathValue("userID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, impact)
}

func (h *IdentityHandler) getIdentityUserDisableImpact(w http.ResponseWriter, r *http.Request) {
	impact, err := h.users.UserDisableImpact(r.Context(), strings.TrimSpace(r.PathValue("userID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, impact)
}

func (h *IdentityHandler) enableIdentityUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	if err := h.users.EnableUser(r.Context(), userID); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_enabled", "identity_user", userID, "Re-enabled account login without restoring Profile entitlements", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdentityHandler) disableIdentityUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	revokedSessions, err := h.users.DisableUser(r.Context(), userID, h.userSecurity)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_disabled", "identity_user", userID, "Disabled identity user", map[string]any{"revoked_sessions": revokedSessions, "business_identities_preserved": true})
	w.WriteHeader(http.StatusNoContent)
}
