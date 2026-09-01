package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityPermissionCatalogApplicationService struct {
	repository identityrepository.IdentityPermissionDefinitionRepository
	registry   *IdentityActionRegistry
	workspace  string
	snapshot   atomic.Pointer[identityPermissionRuntimeSnapshot]
}

type identityPermissionRuntimeSnapshot struct {
	byKey map[string]identityPermissionRuntimeState
}

type identityPermissionRuntimeState struct {
	active  bool
	enabled bool
}

func NewIdentityPermissionCatalogApplicationService(repository identityrepository.IdentityPermissionDefinitionRepository, registry *IdentityActionRegistry, workspaceID string) (*IdentityPermissionCatalogApplicationService, error) {
	if repository == nil {
		return nil, fmt.Errorf("Identity permission definition repository is required")
	}
	if registry == nil {
		return nil, fmt.Errorf("Identity action registry is required")
	}
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	return &IdentityPermissionCatalogApplicationService{repository: repository, registry: registry, workspace: workspace.String()}, nil
}

func (service *IdentityPermissionCatalogApplicationService) ReconcileOwner(ctx context.Context, sourceOwner string) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	sourceOwner = strings.TrimSpace(sourceOwner)
	if sourceOwner == "" {
		return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission source owner is required")
	}
	current, err := service.repository.ListIdentityPermissionDefinitions(ctx, service.workspace)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	previousSnapshotHash := ""
	for _, definition := range current {
		if definition.SourceOwner != sourceOwner {
			continue
		}
		if previousSnapshotHash == "" {
			previousSnapshotHash = definition.SourceSnapshotHash
			continue
		}
		if definition.SourceSnapshotHash != previousSnapshotHash {
			return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission owner %q has inconsistent stored snapshot hashes", sourceOwner)
		}
	}
	definitions := service.registry.OwnedPermissionDefinitions(sourceOwner)
	for index := range definitions {
		definition := &definitions[index]
		definition.WorkspaceID = service.workspace
		definition.DefinitionStatus = identitymodel.IdentityPermissionDefinitionActive
		definition.Enabled = true
		definition.DefinitionHash, err = IdentityPermissionDefinitionHash(*definition)
		if err != nil {
			return identitymodel.IdentityPermissionReconcileReceipt{}, err
		}
	}
	snapshotHash, err := IdentityPermissionSourceSnapshotHash(definitions)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	for index := range definitions {
		definitions[index].SourceSnapshotHash = snapshotHash
	}
	receipt, err := service.repository.ReconcileIdentityPermissionDefinitions(ctx, identitymodel.IdentityPermissionReconcileRequest{
		WorkspaceID: service.workspace, SourceOwner: sourceOwner, PreviousSnapshotHash: previousSnapshotHash,
		SnapshotHash: snapshotHash, Definitions: definitions,
	})
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if err := service.refreshRuntimeSnapshot(ctx); err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("reload reconciled Identity permission snapshot: %w", err)
	}
	return receipt, nil
}

// PermissionIsExecutable is the request-path view of current permission
// state. Reconcile compiles database rows into an immutable map so route gates
// neither query the database nor observe a partially replaced snapshot.
func (service *IdentityPermissionCatalogApplicationService) PermissionIsExecutable(permissionKey string) bool {
	if service == nil {
		return false
	}
	snapshot := service.snapshot.Load()
	if snapshot == nil {
		return false
	}
	state, found := snapshot.byKey[strings.TrimSpace(permissionKey)]
	return found && state.active && state.enabled
}

// ValidateNewPermissionSelections permits legacy or retired keys to remain on
// an existing RoleSchema while requiring every newly granted key to come from
// the current active+enabled PermissionDefinition snapshot.
func (service *IdentityPermissionCatalogApplicationService) ValidateNewPermissionSelections(current, requested []string) error {
	if service == nil {
		return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	snapshot := service.snapshot.Load()
	if snapshot == nil {
		return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	existing := make(map[string]struct{}, len(current))
	for _, key := range current {
		if key = strings.TrimSpace(key); key != "" {
			existing[key] = struct{}{}
		}
	}
	for _, raw := range requested {
		key := strings.TrimSpace(raw)
		if key == "" {
			continue
		}
		if _, retained := existing[key]; retained {
			continue
		}
		state, found := snapshot.byKey[key]
		switch {
		case !found:
			return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_not_found", Params: map[string]string{"permission": key}}
		case !state.active:
			return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_retired", Params: map[string]string{"permission": key}}
		case !state.enabled:
			return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_disabled", Params: map[string]string{"permission": key}}
		}
	}
	return nil
}

func (service *IdentityPermissionCatalogApplicationService) refreshRuntimeSnapshot(ctx context.Context) error {
	records, err := service.repository.ListIdentityPermissionDefinitions(ctx, service.workspace)
	if err != nil {
		return err
	}
	byKey := make(map[string]identityPermissionRuntimeState, len(records))
	for _, record := range records {
		byKey[record.PermissionKey] = identityPermissionRuntimeState{
			active:  record.DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive,
			enabled: record.Enabled,
		}
	}
	service.snapshot.Store(&identityPermissionRuntimeSnapshot{byKey: byKey})
	return nil
}

func (service *IdentityPermissionCatalogApplicationService) List(ctx context.Context) ([]identitymodel.IdentityPermissionDefinition, error) {
	records, err := service.repository.ListIdentityPermissionDefinitions(ctx, service.workspace)
	if err != nil {
		return nil, err
	}
	out := make([]identitymodel.IdentityPermissionDefinition, 0, len(records))
	for _, record := range records {
		system, _, _ := IdentityParsePermissionKey(record.PermissionKey)
		usages := service.registry.PermissionUsages(record.PermissionKey)
		point := identitymodel.IdentityPermissionDefinition{
			Key: record.PermissionKey, Label: record.Label, System: system,
			Resource: record.ResourceKey, ResourceLabel: record.ResourceKey, Action: record.ActionKey,
			Category: record.Category, Description: record.Description, SourceType: record.SourceKind,
			DefinitionStatus: record.DefinitionStatus, Enabled: record.Enabled, SourceKind: record.SourceKind,
			SourceOwner: record.SourceOwner, DefinitionHash: record.DefinitionHash, SourceSnapshotHash: record.SourceSnapshotHash,
			ActionUsages: usages,
		}
		if len(usages) > 0 {
			point.SourceActionKey = usages[0].ActionKey
			point.ActionLabel = usages[0].ActionLabel
			point.AuthorizationStrategy = usages[0].AuthorizationStrategy
			point.RiskLevel = usages[0].RiskLevel
			point.ApprovalRequired = usages[0].ApprovalRequired
			point.AssuranceRequired = append([]string(nil), usages[0].AssuranceRequired...)
			point.LifecycleStatus = usages[0].LifecycleStatus
		}
		out = append(out, point)
	}
	return out, nil
}

func IdentityPermissionDefinitionHash(definition identitymodel.IdentityPermissionDefinitionRecord) (string, error) {
	canonical := struct {
		PermissionKey string `json:"permission_key"`
		ResourceKey   string `json:"resource_key"`
		ActionKey     string `json:"action_key"`
		Label         string `json:"label"`
		Description   string `json:"description"`
		Category      string `json:"category"`
		SourceKind    string `json:"source_kind"`
		SourceOwner   string `json:"source_owner"`
	}{
		PermissionKey: strings.TrimSpace(definition.PermissionKey), ResourceKey: strings.TrimSpace(definition.ResourceKey),
		ActionKey: strings.TrimSpace(definition.ActionKey), Label: strings.TrimSpace(definition.Label),
		Description: strings.TrimSpace(definition.Description), Category: strings.TrimSpace(definition.Category),
		SourceKind: strings.TrimSpace(definition.SourceKind), SourceOwner: strings.TrimSpace(definition.SourceOwner),
	}
	if canonical.PermissionKey == "" || canonical.ResourceKey == "" || canonical.ActionKey == "" || canonical.Label == "" || canonical.Category == "" || canonical.SourceKind == "" || canonical.SourceOwner == "" {
		return "", fmt.Errorf("Identity permission definition is incomplete")
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func IdentityPermissionSourceSnapshotHash(definitions []identitymodel.IdentityPermissionDefinitionRecord) (string, error) {
	type entry struct {
		PermissionKey  string `json:"permission_key"`
		DefinitionHash string `json:"definition_hash"`
	}
	values := make([]entry, 0, len(definitions))
	seen := map[string]bool{}
	for _, definition := range definitions {
		key := strings.TrimSpace(definition.PermissionKey)
		hash := strings.TrimSpace(definition.DefinitionHash)
		if key == "" || hash == "" || seen[key] {
			return "", fmt.Errorf("Identity permission snapshot contains an empty or duplicate definition")
		}
		seen[key] = true
		values = append(values, entry{PermissionKey: key, DefinitionHash: hash})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].PermissionKey < values[j].PermissionKey })
	raw, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
