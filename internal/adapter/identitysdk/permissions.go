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
	if adapter.binding == nil || adapter.binding.permissions == nil || adapter.binding.applications == nil {
		return identitysdk.PermissionReconcileReceipt{}, &identitysdk.Error{Code: "identity.permission_registry_unavailable"}
	}
	workspaceID := string(request.Application.WorkspaceID)
	if workspaceID != adapter.binding.permissions.WorkspaceID() || workspaceID != adapter.binding.applications.WorkspaceID() {
		return identitysdk.PermissionReconcileReceipt{}, &identitysdk.Error{Code: "identity.permission_reconcile_scope_mismatch"}
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, request.Application.WorkspaceID); err != nil {
		return identitysdk.PermissionReconcileReceipt{}, err
	}
	registered, err := adapter.binding.applicationRegistered(ctx, request.Application)
	if err != nil {
		return identitysdk.PermissionReconcileReceipt{}, sdkBoundaryError(err)
	}
	if !registered {
		return identitysdk.PermissionReconcileReceipt{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	sourceOwner := strings.TrimSpace(request.SourceOwner)
	definitions := make([]identitymodel.IdentityPermissionDefinitionRecord, len(request.Definitions))
	for index, definition := range request.Definitions {
		definitions[index] = identitymodel.IdentityPermissionDefinitionRecord{
			PermissionKey: strings.TrimSpace(definition.PermissionKey),
			ResourceKey:   strings.TrimSpace(definition.ResourceKey),
			ActionKey:     strings.TrimSpace(definition.ActionKey),
			Label:         strings.TrimSpace(definition.Label),
			Description:   strings.TrimSpace(definition.Description),
			Category:      strings.TrimSpace(definition.Category),
			SourceKind:    strings.TrimSpace(definition.SourceKind),
			SourceOwner:   sourceOwner,
		}
	}
	receipt, err := adapter.binding.permissions.ReconcileDefinitions(ctx, sourceOwner, request.PreviousSnapshotHash, request.SnapshotHash, definitions)
	if err != nil {
		return identitysdk.PermissionReconcileReceipt{}, sdkBoundaryError(err)
	}
	return identitysdk.PermissionReconcileReceipt{
		WorkspaceID:          identitysdk.WorkspaceID(receipt.WorkspaceID),
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
	if adapter.binding == nil || adapter.binding.permissions == nil || adapter.binding.applications == nil {
		return identitysdk.PermissionSourceSnapshot{}, &identitysdk.Error{Code: "identity.permission_snapshot_reader_unavailable"}
	}
	workspaceID := string(request.Application.WorkspaceID)
	if workspaceID != adapter.binding.permissions.WorkspaceID() || workspaceID != adapter.binding.applications.WorkspaceID() {
		return identitysdk.PermissionSourceSnapshot{}, &identitysdk.Error{Code: "identity.permission_snapshot_scope_mismatch"}
	}
	registered, err := adapter.binding.applicationRegistered(ctx, request.Application)
	if err != nil {
		return identitysdk.PermissionSourceSnapshot{}, sdkBoundaryError(err)
	}
	if !registered {
		return identitysdk.PermissionSourceSnapshot{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	sourceOwner := strings.TrimSpace(request.SourceOwner)
	hash, current, err := adapter.binding.permissions.CurrentSourceSnapshot(ctx, sourceOwner)
	if err != nil {
		return identitysdk.PermissionSourceSnapshot{}, sdkBoundaryError(err)
	}
	definitions := make([]identitysdk.PermissionDefinition, len(current))
	for index, definition := range current {
		definitions[index] = identitysdk.PermissionDefinition{
			PermissionKey: definition.PermissionKey, ResourceKey: definition.ResourceKey, ActionKey: definition.ActionKey,
			Label: definition.Label, Description: definition.Description, Category: definition.Category, SourceKind: definition.SourceKind,
		}
	}
	return identitysdk.PermissionSourceSnapshot{
		WorkspaceID: request.Application.WorkspaceID, SourceOwner: sourceOwner, SnapshotHash: hash, Definitions: definitions,
	}, nil
}

var _ identitysdk.PermissionSnapshotReader = sdkPermissions{}
