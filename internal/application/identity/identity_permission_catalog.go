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

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/logging"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityPermissionCatalogApplicationService struct {
	repository          identityrepository.IdentityPermissionDefinitionRepository
	registry            *IdentityActionRegistry
	workspace           string
	hostWorkspaceScopes bool
	snapshot            atomic.Pointer[identityPermissionRuntimeSnapshot]
	usage               atomic.Pointer[identityActionUsageProvider]
}

type identityActionUsageProvider struct {
	provider actioncontract.PermissionUsageProvider
}

func (service *IdentityPermissionCatalogApplicationService) WorkspaceID() string {
	if service == nil {
		return ""
	}
	return service.workspace
}

type identityPermissionRuntimeSnapshot struct {
	byKey       map[string]identityPermissionRuntimeState
	definitions map[string]identitymodel.IdentityPermissionDefinition
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

// ForWorkspace creates an independent catalog; cached state is never shared
// across workspace scopes. Only the host's immutable usage provider is shared.
func (service *IdentityPermissionCatalogApplicationService) ForWorkspace(workspaceID string) (*IdentityPermissionCatalogApplicationService, error) {
	if workspaceID == service.workspace {
		return service, nil
	}
	scoped, err := NewIdentityPermissionCatalogApplicationService(service.repository, service.registry, workspaceID)
	if err == nil {
		scoped.usage.Store(service.usage.Load())
		scoped.hostWorkspaceScopes = service.hostWorkspaceScopes
	}
	return scoped, err
}

// EnableHostWorkspaceScopes is called only during embedded assembly.
func (service *IdentityPermissionCatalogApplicationService) EnableHostWorkspaceScopes() {
	service.hostWorkspaceScopes = true
}

// WorkspacePermissionDefinitions returns a request-local snapshot, including
// this workspace's own administrator switches. No mutable scope is shared.
func (service *IdentityPermissionCatalogApplicationService) WorkspacePermissionDefinitions(ctx context.Context, workspaceID string) (map[string]identitymodel.IdentityPermissionDefinition, error) {
	if !service.hostWorkspaceScopes {
		return service.PermissionDefinitions(), nil
	}
	scoped, err := service.ForWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	records, err := service.repository.ListIdentityPermissionDefinitions(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	definitions := make(map[string]identitymodel.IdentityPermissionDefinition, len(records))
	for _, record := range records {
		definitions[record.PermissionKey] = scoped.projectDefinition(record)
	}
	return definitions, nil
}

// UseActionUsageProvider binds the host-owned live registry query. Embedded
// Runtime supplies an in-process provider; standalone Identity supplies a
// remote Runtime provider. Permission definitions and usages remain separate
// authorities and no usage is copied into persistence.
func (service *IdentityPermissionCatalogApplicationService) UseActionUsageProvider(provider actioncontract.PermissionUsageProvider) error {
	if service == nil || provider == nil {
		return fmt.Errorf("Identity Action usage provider is required")
	}
	service.usage.Store(&identityActionUsageProvider{provider: provider})
	return nil
}

func (service *IdentityPermissionCatalogApplicationService) ReconcileOwner(ctx context.Context, sourceOwner string) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	if service == nil || service.registry == nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, fmt.Errorf("Identity permission catalog is unavailable")
	}
	sourceOwner = strings.TrimSpace(sourceOwner)
	definitions := service.registry.OwnedPermissionDefinitions(sourceOwner)
	previousSnapshotHash, err := service.CurrentSourceSnapshotHash(ctx, sourceOwner)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	snapshotHash, err := identityPermissionSnapshotHash(sourceOwner, definitions)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	return service.ReconcileDefinitions(ctx, sourceOwner, previousSnapshotHash, snapshotHash, definitions)
}

// ReconcileDefinitions applies one canonical owner's complete Permission
// snapshot. Runtime and module owners use this boundary directly; RoleSchema
// references are never accepted as definition input.
func (service *IdentityPermissionCatalogApplicationService) ReconcileDefinitions(ctx context.Context, sourceOwner, previousSnapshotHash, snapshotHash string, definitions []identitymodel.IdentityPermissionDefinitionRecord) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	sourceOwner = strings.TrimSpace(sourceOwner)
	if sourceOwner == "" {
		return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_source_owner_invalid"}
	}
	previousSnapshotHash = strings.TrimSpace(previousSnapshotHash)
	snapshotHash = strings.TrimSpace(snapshotHash)
	seen := make(map[string]struct{}, len(definitions))
	definitions = append([]identitymodel.IdentityPermissionDefinitionRecord(nil), definitions...)
	for index := range definitions {
		definition := &definitions[index]
		definition.PermissionKey = strings.TrimSpace(definition.PermissionKey)
		definition.ResourceKey = strings.TrimSpace(definition.ResourceKey)
		definition.OperationKey = strings.TrimSpace(definition.OperationKey)
		definition.SourceOwner = strings.TrimSpace(definition.SourceOwner)
		if definition.SourceOwner != sourceOwner {
			return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_owner_scope_mismatch", Params: map[string]string{"permission_key": definition.PermissionKey, "source_owner": sourceOwner}}
		}
		if _, duplicate := seen[definition.PermissionKey]; definition.PermissionKey == "" || duplicate {
			return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_definition_duplicate", Params: map[string]string{"permission_key": definition.PermissionKey}}
		}
		if definition.PermissionKey != definition.ResourceKey+"."+definition.OperationKey {
			return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_definition_invalid", Params: map[string]string{"permission_key": definition.PermissionKey}}
		}
		seen[definition.PermissionKey] = struct{}{}
	}
	ctx = requestcontext.WithWorkspaceID(ctx, service.workspace)
	if requestcontext.RequestID(ctx) == "" {
		ctx = requestcontext.WithRequestID(ctx, requestcontext.NewRequestID())
	}
	var err error
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
	calculatedSnapshotHash, err := IdentityPermissionSourceSnapshotHash(definitions)
	if err != nil {
		return identitymodel.IdentityPermissionReconcileReceipt{}, err
	}
	if snapshotHash == "" || snapshotHash != calculatedSnapshotHash {
		return identitymodel.IdentityPermissionReconcileReceipt{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_snapshot_hash_invalid", Params: map[string]string{"source_owner": sourceOwner}}
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
	// This records the reconcile receipt, not an outer host transaction commit.
	// Embedded callers retain commit/rollback ownership and must record their
	// final transaction outcome at that boundary.
	logging.FromContext(ctx).Info("identity_permission_reconcile_applied", logging.Fields(map[string]any{
		"source_owner": sourceOwner, "snapshot_hash": receipt.SnapshotHash,
		"inserted": receipt.Inserted, "updated": receipt.Updated,
		"retired": receipt.Retired, "unchanged": receipt.Unchanged,
	})...)
	return receipt, nil
}

func (service *IdentityPermissionCatalogApplicationService) CurrentSourceSnapshotHash(ctx context.Context, sourceOwner string) (string, error) {
	hash, _, err := service.CurrentSourceSnapshot(ctx, sourceOwner)
	return hash, err
}

// CurrentSourceSnapshot returns the authoritative CAS baseline and the exact
// active source definitions represented by it. The definition batch lets a
// multi-owner host compensate a partially applied startup reconcile even
// after a process restart; retired history and administrator-owned enabled
// state are deliberately excluded.
func (service *IdentityPermissionCatalogApplicationService) CurrentSourceSnapshot(ctx context.Context, sourceOwner string) (string, []identitymodel.IdentityPermissionDefinitionRecord, error) {
	if service == nil || service.repository == nil {
		return "", nil, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	sourceOwner = strings.TrimSpace(sourceOwner)
	if sourceOwner == "" {
		return "", nil, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "identity.permission_source_owner_invalid"}
	}
	ctx = requestcontext.WithWorkspaceID(ctx, service.workspace)
	current, err := service.repository.ListIdentityPermissionDefinitions(ctx, service.workspace)
	if err != nil {
		return "", nil, err
	}
	snapshotHash := ""
	definitions := []identitymodel.IdentityPermissionDefinitionRecord{}
	for _, definition := range current {
		if definition.SourceOwner != sourceOwner {
			continue
		}
		if snapshotHash == "" {
			snapshotHash = definition.SourceSnapshotHash
		} else if definition.SourceSnapshotHash != snapshotHash {
			return "", nil, &apperror.AppError{Kind: apperror.KindInternal, Code: "identity.permission_snapshot_inconsistent", Params: map[string]string{"source_owner": sourceOwner}}
		}
		if definition.DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive {
			definitions = append(definitions, definition)
		}
	}
	return snapshotHash, definitions, nil
}

func identityPermissionSnapshotHash(sourceOwner string, definitions []identitymodel.IdentityPermissionDefinitionRecord) (string, error) {
	definitions = append([]identitymodel.IdentityPermissionDefinitionRecord(nil), definitions...)
	for index := range definitions {
		definitions[index].SourceOwner = strings.TrimSpace(sourceOwner)
		definitionHash, err := IdentityPermissionDefinitionHash(definitions[index])
		if err != nil {
			return "", err
		}
		definitions[index].DefinitionHash = definitionHash
	}
	return IdentityPermissionSourceSnapshotHash(definitions)
}

type IdentityPermissionEnablementResult struct {
	PermissionKey string `json:"permission_key"`
	Before        bool   `json:"before"`
	Enabled       bool   `json:"enabled"`
	Changed       bool   `json:"changed"`
}

// SetEnabled changes only the administrator-owned switch and reloads the
// atomic snapshot before returning. Source metadata and lifecycle remain under
// reconcile ownership.
func (service *IdentityPermissionCatalogApplicationService) SetEnabled(ctx context.Context, permissionKey string, enabled bool) (IdentityPermissionEnablementResult, error) {
	if service != nil && service.hostWorkspaceScopes {
		workspaceID := requestcontext.WorkspaceID(ctx)
		if workspaceID == "" {
			return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required"}
		}
		if workspaceID != service.workspace {
			scoped, err := service.ForWorkspace(workspaceID)
			if err != nil {
				return IdentityPermissionEnablementResult{}, err
			}
			return scoped.SetEnabled(ctx, permissionKey, enabled)
		}
	}

	if service == nil || service.repository == nil {
		return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	permissionKey = strings.TrimSpace(permissionKey)
	if permissionKey == "" {
		return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_key_required"}
	}
	if !enabled && permissionKey == "identity.permissions.set_enabled" {
		return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_recovery_capability_required", Params: map[string]string{"permission": permissionKey}}
	}
	ctx = requestcontext.WithWorkspaceID(ctx, service.workspace)
	current, found, err := service.repository.GetIdentityPermissionDefinition(ctx, service.workspace, permissionKey)
	if err != nil {
		return IdentityPermissionEnablementResult{}, err
	}
	if !found {
		return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindNotFound, Code: "backend.identity.permission_not_found", Params: map[string]string{"permission": permissionKey}}
	}
	if current.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive {
		return IdentityPermissionEnablementResult{}, &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_retired", Params: map[string]string{"permission": permissionKey}}
	}
	changed, err := service.repository.SetIdentityPermissionDefinitionEnabled(ctx, service.workspace, permissionKey, enabled)
	if err != nil {
		return IdentityPermissionEnablementResult{}, err
	}
	if err := service.refreshRuntimeSnapshot(ctx); err != nil {
		return IdentityPermissionEnablementResult{}, fmt.Errorf("reload Identity permission snapshot after enablement change: %w", err)
	}
	return IdentityPermissionEnablementResult{PermissionKey: permissionKey, Before: current.Enabled, Enabled: enabled, Changed: changed}, nil
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

// PermissionDefinitions exposes a cloned view of the same atomic snapshot
// used by request authorization. Identity principal construction consumes this
// domain port, so database state has one in-process authority.
func (service *IdentityPermissionCatalogApplicationService) PermissionDefinitions() map[string]identitymodel.IdentityPermissionDefinition {
	if service == nil {
		return map[string]identitymodel.IdentityPermissionDefinition{}
	}
	snapshot := service.snapshot.Load()
	if snapshot == nil {
		return map[string]identitymodel.IdentityPermissionDefinition{}
	}
	out := make(map[string]identitymodel.IdentityPermissionDefinition, len(snapshot.definitions))
	for key, definition := range snapshot.definitions {
		out[key] = definition
	}
	return out
}

// ReloadCurrentSnapshot replaces the request-path cache from the database.
// Assembly calls this only after reconciliation or an administrative state
// change; request authorization never performs this I/O.
func (service *IdentityPermissionCatalogApplicationService) ReloadCurrentSnapshot(ctx context.Context) error {
	if service == nil {
		return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	return service.refreshRuntimeSnapshot(requestcontext.WithWorkspaceID(ctx, service.workspace))
}

// ValidatePermissionSelections requires every RoleSchema grant to exist in the
// current active and enabled database snapshot. Historical role strings never
// become definitions and never survive a new publication by compatibility.
func (service *IdentityPermissionCatalogApplicationService) ValidatePermissionSelections(requested []string) error {
	if service == nil {
		return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	snapshot := service.snapshot.Load()
	if snapshot == nil {
		return &apperror.AppError{Kind: apperror.KindUnavailable, Code: "backend.identity.permission_catalog_unavailable"}
	}
	for _, raw := range requested {
		key := strings.TrimSpace(raw)
		if key == "" {
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
	definitions := make(map[string]identitymodel.IdentityPermissionDefinition, len(records))
	for _, record := range records {
		byKey[record.PermissionKey] = identityPermissionRuntimeState{
			active:  record.DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive,
			enabled: record.Enabled,
		}
		definitions[record.PermissionKey] = service.projectDefinition(record)
	}
	service.snapshot.Store(&identityPermissionRuntimeSnapshot{byKey: byKey, definitions: definitions})
	return nil
}

func (service *IdentityPermissionCatalogApplicationService) List(ctx context.Context) ([]identitymodel.IdentityPermissionDefinition, error) {
	if service != nil && service.hostWorkspaceScopes {
		workspaceID := requestcontext.WorkspaceID(ctx)
		if workspaceID == "" {
			return nil, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required"}
		}
		if workspaceID != service.workspace {
			scoped, err := service.ForWorkspace(workspaceID)
			if err != nil {
				return nil, err
			}
			return scoped.List(ctx)
		}
	}

	records, err := service.repository.ListIdentityPermissionDefinitions(ctx, service.workspace)
	if err != nil {
		return nil, err
	}
	resolved := service.resolveActionUsages(ctx, records)
	out := make([]identitymodel.IdentityPermissionDefinition, 0, len(records))
	for _, record := range records {
		out = append(out, service.projectDefinitionWithUsage(record, resolved[record.PermissionKey]))
	}
	return out, nil
}

func (service *IdentityPermissionCatalogApplicationService) projectDefinition(record identitymodel.IdentityPermissionDefinitionRecord) identitymodel.IdentityPermissionDefinition {
	resolution := identityActionUsageResolution{
		available: service.registry.PermissionUsageAvailable(record.SourceOwner),
		usages:    service.registry.PermissionUsages(record.PermissionKey),
	}
	return service.projectDefinitionWithUsage(record, resolution)
}

func (service *IdentityPermissionCatalogApplicationService) projectDefinitionWithUsage(record identitymodel.IdentityPermissionDefinitionRecord, resolution identityActionUsageResolution) identitymodel.IdentityPermissionDefinition {
	system, _, _ := identityPermissionKeyParts(record.PermissionKey)
	usageStatus := identitymodel.IdentityActionUsageUnavailable
	if resolution.available {
		usageStatus = identitymodel.IdentityActionUsageAvailable
	}
	usages := cloneIdentityActionPermissionUsages(resolution.usages)
	point := identitymodel.IdentityPermissionDefinition{
		Key: record.PermissionKey, Label: record.Label, System: system,
		Resource: record.ResourceKey, ResourceLabel: record.ResourceKey, Action: record.OperationKey,
		Category: record.Category, Description: record.Description, SourceType: record.SourceKind,
		DefinitionStatus: record.DefinitionStatus, Enabled: record.Enabled, SourceKind: record.SourceKind,
		SourceOwner: record.SourceOwner, DefinitionHash: record.DefinitionHash, SourceSnapshotHash: record.SourceSnapshotHash,
		ActionUsageStatus: usageStatus, ActionUsages: usages,
	}
	if len(usages) > 0 {
		point.SourceActionKey = usages[0].ActionKey
		point.ActionLabel = usages[0].ActionLabel
		point.RiskLevel = usages[0].RiskLevel
		point.ApprovalRequired = usages[0].ApprovalRequired
		point.AssuranceRequired = append([]string(nil), usages[0].AssuranceRequired...)
		point.LifecycleStatus = usages[0].LifecycleStatus
	}
	return point
}

type identityActionUsageResolution struct {
	available bool
	usages    []identitymodel.IdentityActionPermissionUsage
}

func (service *IdentityPermissionCatalogApplicationService) resolveActionUsages(ctx context.Context, records []identitymodel.IdentityPermissionDefinitionRecord) map[string]identityActionUsageResolution {
	resolved := make(map[string]identityActionUsageResolution, len(records))
	external := map[string][]string{}
	for _, record := range records {
		if service.registry.PermissionUsageAvailable(record.SourceOwner) {
			resolved[record.PermissionKey] = identityActionUsageResolution{
				available: true,
				usages:    service.registry.PermissionUsages(record.PermissionKey),
			}
			continue
		}
		external[record.SourceOwner] = append(external[record.SourceOwner], record.PermissionKey)
	}
	provider := service.usage.Load()
	if provider == nil || provider.provider == nil || len(external) == 0 {
		return resolved
	}
	queries := make([]actioncontract.PermissionUsageQuery, 0, len(external))
	for owner, permissionKeys := range external {
		queries = append(queries, actioncontract.PermissionUsageQuery{SourceOwner: owner, PermissionKeys: permissionKeys})
	}
	request, err := actioncontract.NewPermissionUsageRequest(queries)
	if err != nil {
		logging.FromContext(ctx).Warn("identity_action_usage_query_invalid", logging.Fields(map[string]any{"error": err.Error()})...)
		return resolved
	}
	snapshot, err := provider.provider.QueryPermissionUsages(ctx, request)
	if err != nil {
		logging.FromContext(ctx).Warn("identity_action_usage_query_unavailable", logging.Fields(map[string]any{"error": err.Error()})...)
		return resolved
	}
	if err := snapshot.ValidateFor(request); err != nil {
		logging.FromContext(ctx).Warn("identity_action_usage_snapshot_invalid", logging.Fields(map[string]any{"error": err.Error()})...)
		return resolved
	}
	for _, owner := range snapshot.Owners {
		for _, permissionKey := range external[owner.SourceOwner] {
			resolved[permissionKey] = identityActionUsageResolution{available: owner.Available}
		}
		for _, usage := range owner.Usages {
			entry := resolved[usage.Permission.Key]
			entry.available = owner.Available
			entry.usages = append(entry.usages, projectIdentityActionPermissionUsage(usage))
			resolved[usage.Permission.Key] = entry
		}
	}
	return resolved
}

func cloneIdentityActionPermissionUsages(values []identitymodel.IdentityActionPermissionUsage) []identitymodel.IdentityActionPermissionUsage {
	result := make([]identitymodel.IdentityActionPermissionUsage, len(values))
	copy(result, values)
	for index := range result {
		result[index].AssuranceRequired = append([]string(nil), result[index].AssuranceRequired...)
	}
	return result
}

func identityPermissionKeyParts(key string) (string, string, string) {
	parts := strings.Split(strings.TrimSpace(key), ".")
	switch len(parts) {
	case 1:
		return "domain", parts[0], ""
	case 2:
		return "domain", parts[0], parts[1]
	default:
		return parts[0], parts[1], strings.Join(parts[2:], ".")
	}
}

func IdentityPermissionDefinitionHash(definition identitymodel.IdentityPermissionDefinitionRecord) (string, error) {
	canonical := struct {
		PermissionKey string `json:"permission_key"`
		ResourceKey   string `json:"resource_key"`
		OperationKey  string `json:"operation_key"`
		Label         string `json:"label"`
		Description   string `json:"description"`
		Category      string `json:"category"`
		SourceKind    string `json:"source_kind"`
		SourceOwner   string `json:"source_owner"`
	}{
		PermissionKey: strings.TrimSpace(definition.PermissionKey), ResourceKey: strings.TrimSpace(definition.ResourceKey),
		OperationKey: strings.TrimSpace(definition.OperationKey), Label: strings.TrimSpace(definition.Label),
		Description: strings.TrimSpace(definition.Description), Category: strings.TrimSpace(definition.Category),
		SourceKind: strings.TrimSpace(definition.SourceKind), SourceOwner: strings.TrimSpace(definition.SourceOwner),
	}
	if canonical.PermissionKey == "" || canonical.ResourceKey == "" || canonical.OperationKey == "" || canonical.Label == "" || canonical.Category == "" || canonical.SourceKind == "" || canonical.SourceOwner == "" {
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

// ReconcileApplicationSourcesFromWorkspace seeds published source metadata;
// it does not copy grants or administrator-owned enablement.
func (service *IdentityPermissionCatalogApplicationService) ReconcileApplicationSourcesFromWorkspace(ctx context.Context, sourceWorkspaceID string) error {
	records, err := service.repository.ListIdentityPermissionDefinitions(ctx, sourceWorkspaceID)
	if err != nil {
		return err
	}
	owners := map[string][]identitymodel.IdentityPermissionDefinitionRecord{}
	for _, record := range records {
		if record.SourceOwner == IdentityBuiltinAuthorizationOwner {
			continue
		}
		if _, ok := owners[record.SourceOwner]; !ok {
			owners[record.SourceOwner] = nil
		}
		if record.DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive {
			owners[record.SourceOwner] = append(owners[record.SourceOwner], record)
		}
	}
	keys := make([]string, 0, len(owners))
	for key := range owners {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, owner := range keys {
		previous, err := service.CurrentSourceSnapshotHash(ctx, owner)
		if err != nil {
			return err
		}
		hash, err := identityPermissionSnapshotHash(owner, owners[owner])
		if err != nil {
			return err
		}
		if _, err := service.ReconcileDefinitions(ctx, owner, previous, hash, owners[owner]); err != nil {
			return err
		}
	}
	return nil
}
