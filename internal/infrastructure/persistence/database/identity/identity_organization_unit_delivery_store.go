package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

const (
	organizationUnitOperationOwner = "identity"
	organizationUnitOperationKind  = "identity.organization_unit_delivery"
	organizationUnitStateOwner     = "organization_unit"
)

func (s *SQLIdentityStore) GetIdentityOrganizationUnitDeliveryReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityOrganizationUnitDeliveryReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, false, err
	}
	if !s.OperationsPersistenceBound() {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.Load(ctx, s.reader(ctx), s.sqlRenderer(), workspaceID, organizationUnitOperationOwner, organizationUnitOperationKind, idempotencyKey)
	if err != nil || !found {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, found, err
	}
	var result identitymodel.IdentityOrganizationUnitDeliveryResult
	if err := json.Unmarshal(operation.ResultJSON, &result); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, false, fmt.Errorf("decode Identity organization unit delivery receipt: %w", err)
	}
	if result.DeliveryID != operation.OperationID || result.Organization.OrganizationUnitID != operation.ResourceID {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, false, fmt.Errorf("identity shared organization unit operation scope mismatch")
	}
	return identitymodel.IdentityOrganizationUnitDeliveryReceipt{
		WorkspaceID: workspaceID, ActorID: operation.RequestedBy, IdempotencyKey: strings.TrimSpace(idempotencyKey),
		RequestFingerprint: operation.RequestFingerprint, Result: result, CreatedAt: operation.CreatedAt,
	}, true, nil
}

func (s *SQLIdentityStore) GetIdentityOrganizationUnitDeliveryState(ctx context.Context, workspaceID, organizationID string) (identitymodel.IdentityOrganizationUnitDeliveryState, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Columns("organization_unit_id", "delivery_version", "delivery_state_fingerprint", "updated_at").
		Where(query.And(query.Equal("organization_unit_id", strings.TrimSpace(organizationID)), query.Equal("delivery_owner", organizationUnitStateOwner))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, fmt.Errorf("build Identity organization unit delivery state query: %w", err)
	}
	var state identitymodel.IdentityOrganizationUnitDeliveryState
	var updatedAt int64
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&state.OrganizationID, &state.Version, &state.StateFingerprint, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, err
	}
	state.WorkspaceID = workspaceID
	state.UpdatedAt = timeString(updatedAt)
	return state, true, nil
}

// ResolveIdentityDeliveredOrganizationUnit joins the canonical child to its
// persisted active parent and applies the exact Permission scope to that parent
// in SQL. The caller cannot supply or forge a parent ID for authorization.
func (s *SQLIdentityStore) ResolveIdentityDeliveredOrganizationUnit(ctx context.Context, workspaceID, organizationID string, nodeType identitymodel.IdentityOrganizationUnitType, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityDeliveredOrganizationUnit, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, err
	}
	if strings.TrimSpace(organizationID) == "" || !validOrganizationUnitDeliveryNodeType(nodeType) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, organizationUnitDeliveryStoreError(apperror.KindBadRequest, "backend.identity.organization_unit_projection_invalid")
	}
	scope = scope.Normalized()
	childPhysicalID := query.QualifiedColumn("child", "id")
	childID := query.QualifiedColumn("child", "organization_unit_id")
	parentID := query.QualifiedColumn("parent", "organization_unit_id")
	predicates := []query.Predicate{
		query.EqualValue(childID, strings.TrimSpace(organizationID)),
		query.EqualValue(query.QualifiedColumn("child", "node_type"), string(nodeType)),
		query.EqualValue(query.QualifiedColumn("parent", "status"), string(identitymodel.IdentityStatusActive)),
		validOrganizationUnitDeliveryParentTypePredicate(),
	}
	if !scope.Unrestricted {
		if len(scope.OwnerOrgIDs) == 0 {
			predicates = append(predicates, query.AlwaysFalse())
		} else {
			values := make([]any, len(scope.OwnerOrgIDs))
			for index := range scope.OwnerOrgIDs {
				values[index] = scope.OwnerOrgIDs[index]
			}
			predicates = append(predicates, query.InExpression(parentID, values...))
		}
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Alias("child").
		Projections(
			query.Project(childPhysicalID), query.Project(childID), query.Project(query.QualifiedColumn("child", "code")), query.Project(query.QualifiedColumn("child", "name")),
			query.Project(query.QualifiedColumn("child", "node_type")), query.Project(query.QualifiedColumn("child", "status")), query.Project(parentID), query.Project(query.QualifiedColumn("parent", "node_type")),
			query.Project(query.QualifiedColumn("child", "path")), query.Project(query.QualifiedColumn("child", "ancestor_ids")),
			query.Project(query.QualifiedColumn("child", "depth")), query.Project(query.QualifiedColumn("child", "sort_order")),
			query.Project(query.QualifiedColumn("child", "delivery_version")),
			query.Project(query.QualifiedColumn("child", "delivery_state_fingerprint")),
		).
		Join(
			query.InnerJoin("_identity_organization_units", "parent", query.And(
				query.EqualExpressions(query.QualifiedColumn("parent", "workspace_id"), query.QualifiedColumn("child", "workspace_id")),
				query.EqualExpressions(parentID, query.QualifiedColumn("child", "parent_id")),
			)),
		).
		Where(query.And(predicates...)).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, fmt.Errorf("build Identity organization unit delivery projection: %w", err)
	}
	var item identitymodel.IdentityDeliveredOrganizationUnit
	var ancestorsJSON, stateFingerprint string
	var parentNodeType identitymodel.IdentityOrganizationUnitType
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(
		&item.ID, &item.OrganizationUnitID, &item.Code, &item.Name, &item.NodeType, &item.Status, &item.ParentOrganizationID,
		&parentNodeType, &item.Path, &ancestorsJSON, &item.Depth, &item.SortOrder, &item.Version, &stateFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, err
	}
	if !parentNodeType.Valid() {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	if err := json.Unmarshal([]byte(ancestorsJSON), &item.AncestorIDs); err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, fmt.Errorf("decode Identity organization unit delivery ancestors: %w", err)
	}
	if item.Version < 1 {
		item.Version = 1
	}
	if stateFingerprint != "" && stateFingerprint != deliveredOrganizationUnitStoreFingerprint(item) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
	}
	return item, true, nil
}

// ListIdentityOrganizationUnitsPage returns a bounded, type-filtered catalog
// from the canonical organization tree. Node type is data supplied by the
// caller's compiled capability; no product-specific organization kind owns a
// separate directory.
func (s *SQLIdentityStore) ListIdentityOrganizationUnitsPage(ctx context.Context, workspaceID string, nodeType identitymodel.IdentityOrganizationUnitType, scope identitymodel.IdentityDataScopeFilter, afterID int64, fetchLimit int) ([]identitymodel.IdentityDeliveredOrganizationUnit, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	if !validOrganizationUnitDeliveryNodeType(nodeType) || fetchLimit < 1 || fetchLimit > 101 {
		return nil, organizationUnitDeliveryStoreError(apperror.KindBadRequest, "backend.identity.organization_unit_page_invalid")
	}
	scope = scope.Normalized()
	physicalID := query.QualifiedColumn("unit", "id")
	organizationID := query.QualifiedColumn("unit", "organization_unit_id")
	predicates := []query.Predicate{query.EqualValue(query.QualifiedColumn("unit", "node_type"), string(nodeType))}
	if afterID > 0 {
		predicates = append(predicates, query.GreaterThanExpression(physicalID, afterID))
	}
	if !scope.Unrestricted {
		if len(scope.OwnerOrgIDs) == 0 {
			predicates = append(predicates, query.AlwaysFalse())
		} else {
			values := make([]any, len(scope.OwnerOrgIDs))
			for index := range scope.OwnerOrgIDs {
				values[index] = scope.OwnerOrgIDs[index]
			}
			predicates = append(predicates, query.InExpression(organizationID, values...))
		}
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Alias("unit").
		Projections(
			query.Project(physicalID), query.Project(organizationID), query.Project(query.QualifiedColumn("unit", "code")),
			query.Project(query.QualifiedColumn("unit", "name")), query.Project(query.QualifiedColumn("unit", "node_type")),
			query.Project(query.QualifiedColumn("unit", "status")), query.Project(query.QualifiedColumn("unit", "parent_id")),
			query.Project(query.QualifiedColumn("unit", "path")), query.Project(query.QualifiedColumn("unit", "ancestor_ids")),
			query.Project(query.QualifiedColumn("unit", "depth")), query.Project(query.QualifiedColumn("unit", "sort_order")),
			query.Project(query.QualifiedColumn("unit", "delivery_version")),
		).
		Join(query.InnerJoin("_identity_organization_units", "parent", query.And(
			query.EqualExpressions(query.QualifiedColumn("parent", "workspace_id"), query.QualifiedColumn("unit", "workspace_id")),
			query.EqualExpressions(query.QualifiedColumn("parent", "organization_unit_id"), query.QualifiedColumn("unit", "parent_id")),
		))).
		Where(query.And(predicates...)).OrderBy(query.AscendingExpression(physicalID)).Limit(fetchLimit).Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity organization unit page query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityDeliveredOrganizationUnit, 0, fetchLimit)
	for rows.Next() {
		var item identitymodel.IdentityDeliveredOrganizationUnit
		var ancestorsJSON string
		if err := rows.Scan(&item.ID, &item.OrganizationUnitID, &item.Code, &item.Name, &item.NodeType, &item.Status, &item.ParentOrganizationID, &item.Path, &ancestorsJSON, &item.Depth, &item.SortOrder, &item.Version); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ancestorsJSON), &item.AncestorIDs); err != nil {
			return nil, fmt.Errorf("decode Identity organization unit ancestors: %w", err)
		}
		if item.Version < 1 {
			item.Version = 1
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *SQLIdentityStore) ExecuteIdentityOrganizationUnitDelivery(ctx context.Context, mutation identitymodel.IdentityOrganizationUnitDeliveryMutation) (identitymodel.IdentityOrganizationUnitDeliveryReceipt, error) {
	executor := identitytransaction.ExecutorFromContext(ctx)
	if executor == nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindInternal, "backend.identity.organization_unit_transaction_required")
	}
	parentID := identityOrganizationUnitDeliveryParentID(mutation.Organization.ParentID)
	if strings.TrimSpace(mutation.WorkspaceID) == "" || strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" || strings.TrimSpace(mutation.Organization.OrganizationUnitID) == "" || parentID == "" || !validOrganizationUnitDeliveryNodeType(mutation.Organization.NodeType) || !identityOrganizationUnitOperationValid(mutation.Operation) {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
	}
	if !s.OperationsPersistenceBound() {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	if !organizationUnitDeliveryMutationScopeAllows(mutation.DataScope, mutation.Operation, mutation.Organization) {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindForbidden, "backend.identity.organization_unit_scope_denied")
	}
	if receipt, found, err := s.GetIdentityOrganizationUnitDeliveryReceipt(ctx, mutation.WorkspaceID, mutation.IdempotencyKey); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Result.Replayed = true
		return receipt, nil
	}
	currentVersion := int64(0)
	switch mutation.Operation {
	case identitymodel.IdentityOrganizationUnitCreate:
		if mutation.ExpectedVersion != 0 {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		parent, found, err := s.LockIdentityOrganizationUnitDeliveryParent(ctx, mutation.WorkspaceID, parentID)
		if err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
		}
		if !found || !parent.NodeType.Valid() || parent.Status != identitymodel.IdentityStatusActive {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_parent_invalid")
		}
		if !identityOrganizationUnitDeliveryHierarchyMatchesParent(mutation.Organization, parent) {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
		}
		if _, found, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, mutation.Organization.OrganizationUnitID, identitymodel.IdentityDataScopeFilter{Unrestricted: true}); err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
		} else if found {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		if err := s.insertDeliveredOrganizationUnit(ctx, executor, mutation.WorkspaceID, mutation.Organization, 1, organizationUnitDeliveryStoreFingerprint(mutation.Organization)); err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, normalizeOrganizationUnitDeliveryWriteError(err)
		}
		currentVersion = 1
	case identitymodel.IdentityOrganizationUnitRename, identitymodel.IdentityOrganizationUnitDisable:
		current, found, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, mutation.Organization.OrganizationUnitID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
		if err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
		}
		if !found || current.NodeType != mutation.Organization.NodeType || organizationUnitDeliveryStoreFingerprint(current) != mutation.CurrentFingerprint {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		state, stateFound, err := s.GetIdentityOrganizationUnitDeliveryState(ctx, mutation.WorkspaceID, mutation.Organization.OrganizationUnitID)
		if err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
		}
		currentVersion = 1
		if stateFound {
			currentVersion = state.Version
			if state.StateFingerprint != mutation.CurrentFingerprint {
				return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_external_change")
			}
		}
		if mutation.ExpectedVersion != currentVersion {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		nextVersion := currentVersion + 1
		updated, err := s.updateDeliveredOrganizationUnitCAS(ctx, executor, mutation.WorkspaceID, current, mutation.Organization, mutation.Operation, stateFound, currentVersion, mutation.CurrentFingerprint, nextVersion, organizationUnitDeliveryStoreFingerprint(mutation.Organization))
		if err != nil {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
		}
		if !updated {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
		}
		currentVersion = nextVersion
	}
	persisted, found, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, mutation.Organization.OrganizationUnitID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
	}
	if !found {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, fmt.Errorf("created Identity organization unit was not found")
	}

	now := nowString()
	result := identitymodel.IdentityOrganizationUnitDeliveryResult{
		DeliveryID:   handlerDeliveryStableID("organization-unit", mutation.WorkspaceID, mutation.IdempotencyKey),
		Organization: identityOrganizationUnitDeliveryStoreProjection(persisted, currentVersion),
	}
	receipt := identitymodel.IdentityOrganizationUnitDeliveryReceipt{
		WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Result: result, CreatedAt: now,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
	}
	relatedIDsJSON, _ := json.Marshal(uniqueHandlerDeliveryStrings([]string{mutation.Organization.OrganizationUnitID, parentID}))
	if err := operationreceipt.InsertSucceeded(ctx, executor, s.sqlRenderer(), operationreceipt.Succeeded{
		OperationID: result.DeliveryID, WorkspaceID: mutation.WorkspaceID, Owner: organizationUnitOperationOwner, Kind: organizationUnitOperationKind,
		ActionKey: "identity.organization_unit." + string(mutation.Operation), ResourceType: "identity_organization_unit", ResourceID: mutation.Organization.OrganizationUnitID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, RequestedBy: mutation.ActorID,
		Reason: "deliver organization unit", ResultJSON: resultJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: now,
	}); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, normalizeOrganizationUnitDeliveryWriteError(err)
	}
	return receipt, nil
}

func (s *SQLIdentityStore) updateDeliveredOrganizationUnitCAS(ctx context.Context, executor identitytransaction.Executor, workspaceID string, current, desired identitymodel.IdentityOrganizationUnit, operation identitymodel.IdentityOrganizationUnitOperation, stateFound bool, expectedVersion int64, expectedFingerprint string, nextVersion int64, nextFingerprint string) (bool, error) {
	currentAncestors, _ := json.Marshal(current.AncestorIDs)
	predicates := []query.Predicate{
		query.Equal("organization_unit_id", current.OrganizationUnitID), query.Equal("code", current.Code), query.Equal("name", current.Name),
		query.Equal("node_type", string(current.NodeType)), query.Equal("parent_id", identityOrganizationUnitDeliveryParentID(current.ParentID)),
		query.Equal("path", current.Path), query.Equal("ancestor_ids", string(currentAncestors)), query.Equal("depth", current.Depth),
		query.Equal("sort_order", current.SortOrder), query.Equal("status", string(current.Status)),
	}
	if stateFound {
		predicates = append(predicates, query.Equal("delivery_owner", organizationUnitStateOwner), query.Equal("delivery_version", expectedVersion), query.Equal("delivery_state_fingerprint", expectedFingerprint))
	} else {
		predicates = append(predicates, query.Equal("delivery_owner", ""), query.Equal("delivery_version", int64(0)), query.Equal("delivery_state_fingerprint", ""))
	}
	update := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Set("delivery_owner", organizationUnitStateOwner).Set("delivery_version", nextVersion).Set("delivery_state_fingerprint", nextFingerprint).Set("updated_at", timeMillis(nowString()))
	switch operation {
	case identitymodel.IdentityOrganizationUnitRename:
		update.Set("name", desired.Name).Set("sibling_key", identitymodel.IdentityOrganizationUnitSiblingKey(desired.ParentID, desired.Name))
	case identitymodel.IdentityOrganizationUnitDisable:
		update.Set("status", string(identitymodel.IdentityStatusDisabled))
	default:
		return false, organizationUnitDeliveryStoreError(apperror.KindBadRequest, "backend.identity.organization_unit_operation_invalid")
	}
	statement, arguments, err := update.Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity organization unit CAS update: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

// LockIdentityOrganizationUnitDeliveryParent takes a write lock without
// changing business state, then reloads the parent through the same host
// transaction. PostgreSQL/MySQL obtain a row lock; SQLite obtains (or fails to
// obtain) its database write reservation. Either outcome prevents a child
// from being inserted from a stale parent snapshot.
func (s *SQLIdentityStore) LockIdentityOrganizationUnitDeliveryParent(ctx context.Context, workspaceID, parentID string) (identitymodel.IdentityOrganizationUnit, bool, error) {
	executor := identitytransaction.ExecutorFromContext(ctx)
	if executor == nil {
		return identitymodel.IdentityOrganizationUnit{}, false, organizationUnitDeliveryStoreError(apperror.KindInternal, "backend.identity.organization_unit_transaction_required")
	}
	statement, arguments, err := buildIdentityOrganizationUnitParentLock(s.sqlRenderer(), workspaceID, parentID)
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, fmt.Errorf("build Identity organization-unit parent lock: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, fmt.Errorf("lock Identity organization-unit parent: %w", err)
	}
	return s.GetIdentityOrganizationUnitWithinDataScope(ctx, workspaceID, parentID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func buildIdentityOrganizationUnitParentLock(renderer ormdialect.Renderer, workspaceID, parentID string) (string, []any, error) {
	return query.NewWorkspaceUpdateBuilder(renderer, "_identity_organization_units", workspaceID).
		SetExpression("updated_at", query.Column("updated_at")).
		Where(query.Equal("organization_unit_id", strings.TrimSpace(parentID))).Build()
}

func identityOrganizationUnitDeliveryHierarchyMatchesParent(organization, parent identitymodel.IdentityOrganizationUnit) bool {
	if identityOrganizationUnitDeliveryParentID(organization.ParentID) != strings.TrimSpace(parent.OrganizationUnitID) || organization.OrganizationUnitID == parent.OrganizationUnitID {
		return false
	}
	expectedAncestors := append(append([]string(nil), parent.AncestorIDs...), parent.OrganizationUnitID)
	if organization.Depth != len(expectedAncestors) || organization.Path != strings.TrimRight(parent.Path, "/")+"/"+organization.OrganizationUnitID || len(organization.AncestorIDs) != len(expectedAncestors) {
		return false
	}
	for index := range expectedAncestors {
		if organization.AncestorIDs[index] != expectedAncestors[index] {
			return false
		}
	}
	return true
}

func (s *SQLIdentityStore) insertDeliveredOrganizationUnit(ctx context.Context, executor identitytransaction.Executor, workspaceID string, organization identitymodel.IdentityOrganizationUnit, version int64, fingerprint string) error {
	ancestors, _ := json.Marshal(organization.AncestorIDs)
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Columns("organization_unit_id", "code", "name", "sibling_key", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "delivery_owner", "delivery_version", "delivery_state_fingerprint", "created_at", "updated_at").
		Values(organization.OrganizationUnitID, organization.Code, organization.Name, identitymodel.IdentityOrganizationUnitSiblingKey(organization.ParentID, organization.Name), string(organization.NodeType), identityOrganizationUnitDeliveryParentID(organization.ParentID), organization.Path, string(ancestors), organization.Depth, organization.SortOrder, string(organization.Status), organizationUnitStateOwner, version, fingerprint, timeMillis(nowString()), timeMillis(nowString())).Build()
	if err != nil {
		return fmt.Errorf("build Identity organization unit delivery insert: %w", err)
	}
	_, err = executor.ExecContext(ctx, statement, arguments...)
	return err
}

func validOrganizationUnitDeliveryNodeType(nodeType identitymodel.IdentityOrganizationUnitType) bool {
	return nodeType.Valid() && nodeType != identitymodel.IdentityOrganizationUnitCompany
}

func validOrganizationUnitDeliveryParentTypePredicate() query.Predicate {
	return query.NotEqualValue(query.QualifiedColumn("parent", "node_type"), "")
}

func identityOrganizationUnitOperationValid(operation identitymodel.IdentityOrganizationUnitOperation) bool {
	return operation == identitymodel.IdentityOrganizationUnitCreate || operation == identitymodel.IdentityOrganizationUnitRename || operation == identitymodel.IdentityOrganizationUnitDisable
}

func organizationUnitDeliveryMutationScopeAllows(scope identitymodel.IdentityDataScopeFilter, operation identitymodel.IdentityOrganizationUnitOperation, organization identitymodel.IdentityOrganizationUnit) bool {
	if scope.Unrestricted {
		return true
	}
	targetID := strings.TrimSpace(organization.OrganizationUnitID)
	if operation == identitymodel.IdentityOrganizationUnitCreate {
		targetID = identityOrganizationUnitDeliveryParentID(organization.ParentID)
	}
	for _, allowed := range scope.Normalized().OwnerOrgIDs {
		if allowed == targetID {
			return true
		}
	}
	return false
}

func identityOrganizationUnitDeliveryParentID(parentID *string) string {
	if parentID == nil {
		return ""
	}
	return strings.TrimSpace(*parentID)
}

func organizationUnitDeliveryStoreFingerprint(organization identitymodel.IdentityOrganizationUnit) string {
	// The database-generated primary key is storage position, not business
	// state. It is unknown before INSERT and must never affect replay checks.
	organization.ID = 0
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func deliveredOrganizationUnitStoreFingerprint(organization identitymodel.IdentityDeliveredOrganizationUnit) string {
	parentID := organization.ParentOrganizationID
	return organizationUnitDeliveryStoreFingerprint(identitymodel.IdentityOrganizationUnit{
		ID: organization.ID, OrganizationUnitID: organization.OrganizationUnitID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		ParentID: &parentID, Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...),
		Depth: organization.Depth, SortOrder: organization.SortOrder, Status: identitymodel.IdentityStatus(organization.Status),
	})
}

func identityOrganizationUnitDeliveryStoreProjection(organization identitymodel.IdentityOrganizationUnit, version int64) identitymodel.IdentityDeliveredOrganizationUnit {
	return identitymodel.IdentityDeliveredOrganizationUnit{
		ID: organization.ID, OrganizationUnitID: organization.OrganizationUnitID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		Status: string(organization.Status), ParentOrganizationID: identityOrganizationUnitDeliveryParentID(organization.ParentID),
		Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...), Depth: organization.Depth,
		SortOrder: organization.SortOrder, Version: version,
	}
}

func normalizeOrganizationUnitDeliveryWriteError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		if strings.Contains(message, "organization_unit_delivery_key") || strings.Contains(message, "idempotency_key") {
			return organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		if strings.Contains(message, "sibling_key") || strings.Contains(message, "uniq_identity_organization_unit_sibling_name") {
			return organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_name_exists")
		}
		if strings.Contains(message, "organization_unit_code") || strings.Contains(message, ".code") {
			return organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_code_exists")
		}
		return organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
	}
	return err
}

func organizationUnitDeliveryStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

var _ identityrepository.IdentityOrganizationUnitDeliveryRepository = (*SQLIdentityStore)(nil)
