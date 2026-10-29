package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkPermissions struct{ binding *sdkBinding }

func (adapter sdkPermissions) Reconcile(ctx context.Context, request identitysdk.PermissionReconcileRequest) (identitysdk.PermissionReconcileReceipt, error) {
	if err := request.ValidateContract(); err != nil {
		return identitysdk.PermissionReconcileReceipt{}, sdkBoundaryError(err)
	}
	if adapter.binding == nil || adapter.binding.permissions == nil {
		return identitysdk.PermissionReconcileReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.permission_registry_unavailable"}
	}
	sourceOwner := strings.TrimSpace(request.SourceOwner)
	definitions := make([]identitymodel.IdentityPermissionDefinitionRecord, len(request.Definitions))
	for index, definition := range request.Definitions {
		definitions[index] = identitymodel.IdentityPermissionDefinitionRecord{
			PermissionKey: strings.TrimSpace(definition.PermissionKey),
			ModuleKey:     strings.TrimSpace(definition.ModuleKey),
			GroupKey:      strings.TrimSpace(definition.GroupKey),
			ResourceKey:   strings.TrimSpace(definition.ResourceKey),
			OperationKey:  strings.TrimSpace(definition.OperationKey),
			Label:         strings.TrimSpace(definition.Label),
			Description:   strings.TrimSpace(definition.Description),
			Category:      strings.TrimSpace(definition.Category),
			SourceKind:    strings.TrimSpace(definition.SourceKind),
			SourceOwner:   sourceOwner,
			GrantMode:     strings.TrimSpace(definition.GrantMode),
			ScopeKind:     strings.TrimSpace(definition.ScopeKind),
			ObjectKey:     strings.TrimSpace(definition.ObjectKey),
			DefaultLocale: strings.TrimSpace(definition.DefaultLocale),
			I18n:          permissionTextFromSDK(definition.I18n),
		}
	}
	receipt, err := adapter.binding.permissions.ReconcileDefinitions(ctx, sourceOwner, request.PreviousSnapshotHash, request.SnapshotHash, definitions)
	if err != nil {
		return identitysdk.PermissionReconcileReceipt{}, sdkBoundaryError(err)
	}
	return identitysdk.PermissionReconcileReceipt{
		SourceOwner:          receipt.SourceOwner,
		PreviousSnapshotHash: receipt.PreviousSnapshotHash,
		SnapshotHash:         receipt.SnapshotHash,
		DefinitionCount:      receipt.DefinitionCount,
		Inserted:             receipt.Inserted,
		Updated:              receipt.Updated,
		Retired:              receipt.Retired,
		Unchanged:            receipt.Unchanged,
	}, nil
}

func (adapter sdkPermissions) CurrentSourceSnapshot(ctx context.Context, request identitysdk.PermissionSourceSnapshotRequest) (identitysdk.PermissionSourceSnapshot, error) {
	if err := request.ValidateContract(); err != nil {
		return identitysdk.PermissionSourceSnapshot{}, sdkBoundaryError(err)
	}
	if adapter.binding == nil || adapter.binding.permissions == nil {
		return identitysdk.PermissionSourceSnapshot{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.permission_snapshot_reader_unavailable"}
	}
	sourceOwner := strings.TrimSpace(request.SourceOwner)
	hash, current, err := adapter.binding.permissions.CurrentSourceSnapshot(ctx, sourceOwner)
	if err != nil {
		return identitysdk.PermissionSourceSnapshot{}, sdkBoundaryError(err)
	}
	definitions := make([]identitysdk.PermissionDefinition, len(current))
	for index, definition := range current {
		definitions[index] = identitysdk.PermissionDefinition{
			PermissionKey: definition.PermissionKey, ModuleKey: definition.ModuleKey, GroupKey: definition.GroupKey,
			ResourceKey: definition.ResourceKey, OperationKey: definition.OperationKey,
			Label: definition.Label, Description: definition.Description, Category: definition.Category, SourceKind: definition.SourceKind,
			GrantMode: definition.GrantMode, ScopeKind: definition.ScopeKind, ObjectKey: definition.ObjectKey,
			DefaultLocale: definition.DefaultLocale, I18n: permissionTextToSDK(definition.I18n),
		}
	}
	return identitysdk.PermissionSourceSnapshot{
		SourceOwner: sourceOwner, SnapshotHash: hash, Definitions: definitions,
	}, nil
}

var _ identitysdk.PermissionSnapshotReader = sdkPermissions{}

func permissionTextFromSDK(source identitysdk.PermissionLocalizedText) identitymodel.IdentityPermissionLocalizedText {
	result := make(identitymodel.IdentityPermissionLocalizedText, len(source))
	for locale, text := range source {
		result[locale] = identitymodel.IdentityPermissionText{
			ModuleLabel: text.ModuleLabel, GroupLabel: text.GroupLabel, ResourceLabel: text.ResourceLabel,
			OperationLabel: text.OperationLabel, Label: text.Label, Description: text.Description,
		}
	}
	return result
}

func permissionTextToSDK(source identitymodel.IdentityPermissionLocalizedText) identitysdk.PermissionLocalizedText {
	result := make(identitysdk.PermissionLocalizedText, len(source))
	for locale, text := range source {
		result[locale] = identitysdk.PermissionText{
			ModuleLabel: text.ModuleLabel, GroupLabel: text.GroupLabel, ResourceLabel: text.ResourceLabel,
			OperationLabel: text.OperationLabel, Label: text.Label, Description: text.Description,
		}
	}
	return result
}
