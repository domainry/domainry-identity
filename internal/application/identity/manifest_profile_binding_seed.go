package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

// SyncManifestIdentityProfileBindings materializes explicit compiler-resolved
// demo-user profile bindings after business seeds exist. Extension metadata is
// discovery only; it must never be mistaken for an active user/profile link.
func SyncManifestIdentityProfileBindings(ctx context.Context, repository identityrepository.IdentityProfileBindingRepository, manifest manifestmodel.ManifestSchema) error {
	if repository == nil || manifest.IdentityBootstrap == nil || len(manifest.IdentityBootstrap.ProfileBindings) == 0 {
		return nil
	}
	workspaceID := manifestIdentityWorkspaceID(ctx)
	for _, seed := range manifest.IdentityBootstrap.ProfileBindings {
		bindingKey := strings.TrimSpace(seed.BindingKey)
		profileID := strings.TrimSpace(seed.ProfileID)
		identityUserID := strings.TrimSpace(seed.IdentityUserID)
		current, found, err := repository.GetIdentityProfileBindingByKey(ctx, workspaceID, bindingKey, profileID)
		if err != nil {
			return fmt.Errorf("read manifest profile binding %s/%s: %w", bindingKey, profileID, err)
		}
		if found {
			if current.Status == identitymodel.IdentityProfileBindingActive && strings.TrimSpace(current.IdentityUserID) == identityUserID && strings.TrimSpace(current.ObjectKey) == strings.TrimSpace(seed.ObjectKey) {
				continue
			}
			return fmt.Errorf("manifest profile binding %s/%s conflicts with existing status=%s identity_user_id=%s", bindingKey, profileID, current.Status, current.IdentityUserID)
		}
		fingerprintInput, _ := json.Marshal(seed)
		fingerprintHash := sha256.Sum256(fingerprintInput)
		mutation := identitymodel.IdentityProfileBindingMutation{
			WorkspaceID: workspaceID, BindingKey: bindingKey, ObjectKey: strings.TrimSpace(seed.ObjectKey), ProfileID: profileID,
			IdentityField: strings.TrimSpace(seed.IdentityField), Operation: identitymodel.IdentityProfileBindingBind, IdentityUserID: identityUserID,
			ExpectedVersion: 0, IdempotencyKey: "manifest-profile-binding:" + bindingKey + ":" + profileID,
			RequestFingerprint: hex.EncodeToString(fingerprintHash[:]), ActorID: "runtime_manifest_seed",
		}
		if _, err := repository.ExecuteIdentityProfileBindingMutation(ctx, mutation); err != nil {
			return fmt.Errorf("sync manifest profile binding %s/%s: %w", bindingKey, profileID, err)
		}
	}
	return nil
}
