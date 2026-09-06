package moduleassembly

import (
	"context"
	"fmt"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type moduleProjectProfileExtensionPublisher struct {
	binding *moduleBinding
}

func (binding *moduleBinding) ProjectProfileExtensionPublisher() identitysdk.ProjectProfileExtensionPublisher {
	return moduleProjectProfileExtensionPublisher{binding: binding}
}

func (publisher moduleProjectProfileExtensionPublisher) PublishProjectProfileExtensions(ctx context.Context, extensions []identitysdk.ProjectProfileExtension) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if publisher.binding == nil || publisher.binding.runtime == nil || publisher.binding.runtime.MetadataRuntime == nil {
		return fmt.Errorf("Identity project Profile Extension publisher is unavailable")
	}
	converted := make([]identitymodel.IdentityProfileExtension, 0, len(extensions))
	seen := map[string]bool{}
	for _, extension := range extensions {
		objectKey := strings.TrimSpace(extension.ObjectKey)
		if objectKey == "" || seen[objectKey] {
			return fmt.Errorf("Identity project Profile Extension object key is missing or duplicated: %q", objectKey)
		}
		seen[objectKey] = true
		claims := make([]identitymodel.BusinessIdentityClaimBinding, 0, len(extension.BusinessIdentity.Claims))
		for _, claim := range extension.BusinessIdentity.Claims {
			claims = append(claims, identitymodel.BusinessIdentityClaimBinding{ClaimKey: claim.ClaimKey, FieldKey: claim.FieldKey})
		}
		proofs := make([]identitymodel.IdentityProfileClaimProof, 0, len(extension.BindingLifecycle.ClaimProofs))
		for _, proof := range extension.BindingLifecycle.ClaimProofs {
			proofs = append(proofs, identitymodel.IdentityProfileClaimProof{Type: proof.Type, FieldKey: proof.FieldKey})
		}
		converted = append(converted, identitymodel.IdentityProfileExtension{
			ContractVersion: extension.ContractVersion, MinReaderVersion: extension.MinReaderVersion, ObjectKey: objectKey,
			IdentityRelationField: extension.IdentityRelationField, Cardinality: extension.Cardinality,
			BusinessIdentity: identitymodel.BusinessIdentityBinding{
				Key: extension.BusinessIdentity.Key, StatusField: extension.BusinessIdentity.StatusField,
				ActiveStatusValues: append([]string(nil), extension.BusinessIdentity.ActiveStatusValues...), BlacklistField: extension.BusinessIdentity.BlacklistField, Claims: claims,
			},
			BindingLifecycle: identitymodel.IdentityProfileBindingLifecycle{
				AllowUnbound: extension.BindingLifecycle.AllowUnbound, InvitationChannels: append([]string(nil), extension.BindingLifecycle.InvitationChannels...), ClaimProofs: proofs,
				RebindRequiresApproval: extension.BindingLifecycle.RebindRequiresApproval, RebindRevokesSessions: extension.BindingLifecycle.RebindRevokesSessions,
			},
			SummaryFields: append([]string(nil), extension.SummaryFields...), ProfileTabs: append([]string(nil), extension.ProfileTabs...),
			ProfileTabLabels: cloneStringMap(extension.ProfileTabLabels), ProfileTabFields: cloneStringSliceMap(extension.ProfileTabFields),
			ProfileTabRelatedObjects: cloneStringSliceMap(extension.ProfileTabRelatedObjects), ProfileTabComponents: cloneStringSliceMap(extension.ProfileTabComponents),
			DefaultVisibility: extension.DefaultVisibility, RequiredPermissions: append([]string(nil), extension.RequiredPermissions...), StandaloneWorkspace: extension.StandaloneWorkspace,
		})
	}
	publisher.binding.runtime.MetadataRuntime.ReplaceProjectProfileExtensions(converted)
	return nil
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStringSliceMap(source map[string][]string) map[string][]string {
	if source == nil {
		return nil
	}
	result := make(map[string][]string, len(source))
	for key, value := range source {
		result[key] = append([]string(nil), value...)
	}
	return result
}

var _ identitysdk.ProjectProfileExtensionPublisher = moduleProjectProfileExtensionPublisher{}
var _ identitysdk.EmbeddedProjectProfileExtensionBinding = (*moduleBinding)(nil)
