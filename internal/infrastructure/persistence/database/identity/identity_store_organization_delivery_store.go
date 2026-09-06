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
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) GetIdentityStoreOrganizationDeliveryReceipt(ctx context.Context, workspaceID, idempotencyKey string) (identitymodel.IdentityStoreOrganizationDeliveryReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_store_organization_deliveries", workspaceID).
		Columns("actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Where(query.Equal("idempotency_key", strings.TrimSpace(idempotencyKey))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, false, fmt.Errorf("build Identity store organization receipt query: %w", err)
	}
	var receipt identitymodel.IdentityStoreOrganizationDeliveryReceipt
	var resultJSON string
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&receipt.ActorID, &receipt.IdempotencyKey, &receipt.RequestFingerprint, &resultJSON, &receipt.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	if err := json.Unmarshal([]byte(resultJSON), &receipt.Result); err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, false, fmt.Errorf("decode Identity store organization receipt: %w", err)
	}
	return receipt, true, nil
}

func (s *SQLIdentityStore) GetIdentityStoreOrganizationState(ctx context.Context, workspaceID, organizationID string) (identitymodel.IdentityStoreOrganizationState, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationState{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_store_organization_states", workspaceID).
		Columns("organization_id", "version", "state_fingerprint", "updated_at").
		Where(query.Equal("organization_id", strings.TrimSpace(organizationID))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityStoreOrganizationState{}, false, fmt.Errorf("build Identity store organization state query: %w", err)
	}
	var state identitymodel.IdentityStoreOrganizationState
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&state.OrganizationID, &state.Version, &state.StateFingerprint, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityStoreOrganizationState{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityStoreOrganizationState{}, false, err
	}
	state.WorkspaceID = workspaceID
	return state, true, nil
}

// ListIdentityStoreOrganizationsPage applies type, Workspace, permission data
// scope, parent-company integrity, cursor, ordering, and the fetch bound in one
// ORM-built query. The joined state row supplies the delivery CAS version, so
// callers never need per-item organization, parent, or version reads.
func (s *SQLIdentityStore) ListIdentityStoreOrganizationsPage(ctx context.Context, workspaceID string, scope identitymodel.IdentityDataScopeFilter, afterID string, fetchLimit int) ([]identitymodel.IdentityStoreOrganization, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	if fetchLimit < 1 || fetchLimit > 101 {
		return nil, storeOrganizationStoreError(apperror.KindBadRequest, "backend.identity.store_organization_page_size_invalid")
	}
	scope = scope.Normalized()
	storeID := query.QualifiedColumn("store", "id")
	predicates := []query.Predicate{
		query.EqualValue(query.QualifiedColumn("store", "node_type"), string(identitymodel.IdentityOrganizationUnitStore)),
	}
	if afterID = strings.TrimSpace(afterID); afterID != "" {
		predicates = append(predicates, query.GreaterThanExpression(storeID, afterID))
	}
	if !scope.Unrestricted {
		if len(scope.OwnerOrgIDs) == 0 {
			predicates = append(predicates, query.AlwaysFalse())
		} else {
			values := make([]any, len(scope.OwnerOrgIDs))
			for index := range scope.OwnerOrgIDs {
				values[index] = scope.OwnerOrgIDs[index]
			}
			predicates = append(predicates, query.InExpression(storeID, values...))
		}
	}
	builder := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Alias("store").
		Projections(
			query.Project(storeID),
			query.Project(query.QualifiedColumn("store", "code")),
			query.Project(query.QualifiedColumn("store", "name")),
			query.Project(query.QualifiedColumn("store", "status")),
			query.Project(query.QualifiedColumn("store", "parent_id")),
			query.Project(query.QualifiedColumn("store", "path")),
			query.Project(query.QualifiedColumn("store", "ancestor_ids")),
			query.Project(query.QualifiedColumn("store", "depth")),
			query.Project(query.QualifiedColumn("store", "sort_order")),
			query.Project(query.Coalesce(query.QualifiedColumn("state", "version"), query.Value(int64(1)))),
		).
		Join(
			query.InnerJoin("_identity_organization_units", "parent", query.And(
				query.EqualExpressions(query.QualifiedColumn("parent", "workspace_id"), query.QualifiedColumn("store", "workspace_id")),
				query.EqualExpressions(query.QualifiedColumn("parent", "id"), query.QualifiedColumn("store", "parent_id")),
				query.EqualValue(query.QualifiedColumn("parent", "node_type"), string(identitymodel.IdentityOrganizationUnitCompany)),
			)),
			query.LeftJoin("_identity_store_organization_states", "state", query.And(
				query.EqualExpressions(query.QualifiedColumn("state", "workspace_id"), query.QualifiedColumn("store", "workspace_id")),
				query.EqualExpressions(query.QualifiedColumn("state", "organization_id"), storeID),
			)),
		).
		Where(query.And(predicates...)).
		OrderBy(query.AscendingExpression(storeID)).
		Limit(fetchLimit)
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build Identity store organization page query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]identitymodel.IdentityStoreOrganization, 0, fetchLimit)
	for rows.Next() {
		var item identitymodel.IdentityStoreOrganization
		var ancestorsJSON string
		if err := rows.Scan(
			&item.ID, &item.Code, &item.Name, &item.Status, &item.ParentOrganizationID,
			&item.Path, &ancestorsJSON, &item.Depth, &item.SortOrder, &item.Version,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ancestorsJSON), &item.AncestorIDs); err != nil {
			return nil, fmt.Errorf("decode Identity store organization ancestors: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *SQLIdentityStore) ExecuteIdentityStoreOrganizationDelivery(ctx context.Context, mutation identitymodel.IdentityStoreOrganizationDeliveryMutation) (identitymodel.IdentityStoreOrganizationDeliveryReceipt, error) {
	executor := identitytransaction.ExecutorFromContext(ctx)
	if executor == nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindInternal, "backend.identity.store_organization_transaction_required")
	}
	if strings.TrimSpace(mutation.WorkspaceID) == "" || strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" || strings.TrimSpace(mutation.Organization.ID) == "" {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindBadRequest, "backend.identity.store_organization_delivery_invalid")
	}
	if receipt, found, err := s.GetIdentityStoreOrganizationDeliveryReceipt(ctx, mutation.WorkspaceID, mutation.IdempotencyKey); err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Result.Replayed = true
		return receipt, nil
	}
	if mutation.Organization.NodeType != identitymodel.IdentityOrganizationUnitStore || identityStoreOrganizationParentID(mutation.Organization) == "" || !storeOrganizationMutationScopeAllows(mutation.DataScope, mutation.Operation, mutation.Organization) {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindForbidden, "backend.identity.store_organization_scope_denied")
	}
	parent, parentFound, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, identityStoreOrganizationParentID(mutation.Organization), identitymodel.IdentityDataScopeFilter{Unrestricted: true})
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
	}
	if !parentFound || parent.NodeType != identitymodel.IdentityOrganizationUnitCompany || (mutation.Operation == identitymodel.IdentityStoreOrganizationCreate && parent.Status != identitymodel.IdentityStatusActive) {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_parent_invalid")
	}

	currentVersion := int64(0)
	switch mutation.Operation {
	case identitymodel.IdentityStoreOrganizationCreate:
		if mutation.ExpectedVersion != 0 {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
		if err := s.insertStoreOrganization(ctx, executor, mutation.WorkspaceID, mutation.Organization); err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, normalizeStoreOrganizationWriteError(err)
		}
		currentVersion = 1
		if err := s.insertStoreOrganizationState(ctx, executor, mutation.WorkspaceID, mutation.Organization.ID, currentVersion, storeOrganizationStateFingerprint(mutation.Organization)); err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, normalizeStoreOrganizationWriteError(err)
		}
	case identitymodel.IdentityStoreOrganizationRename, identitymodel.IdentityStoreOrganizationDisable:
		current, found, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, mutation.Organization.ID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
		if err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
		}
		if !found || current.NodeType != identitymodel.IdentityOrganizationUnitStore || storeOrganizationStateFingerprint(current) != mutation.CurrentFingerprint {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
		state, stateFound, err := s.GetIdentityStoreOrganizationState(ctx, mutation.WorkspaceID, mutation.Organization.ID)
		if err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
		}
		currentVersion = 1
		if stateFound {
			currentVersion = state.Version
			if state.StateFingerprint != mutation.CurrentFingerprint {
				return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_external_change")
			}
		}
		if mutation.ExpectedVersion != currentVersion {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
		updated, err := s.updateStoreOrganizationCAS(ctx, executor, mutation.WorkspaceID, current, mutation.Organization, mutation.Operation)
		if err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
		}
		if !updated {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
		}
		currentVersion++
		if stateFound {
			updated, err := s.updateStoreOrganizationStateCAS(ctx, executor, mutation.WorkspaceID, mutation.Organization.ID, mutation.ExpectedVersion, mutation.CurrentFingerprint, currentVersion, storeOrganizationStateFingerprint(mutation.Organization))
			if err != nil {
				return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
			}
			if !updated {
				return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_version_conflict")
			}
		} else if err := s.insertStoreOrganizationState(ctx, executor, mutation.WorkspaceID, mutation.Organization.ID, currentVersion, storeOrganizationStateFingerprint(mutation.Organization)); err != nil {
			return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, normalizeStoreOrganizationWriteError(err)
		}
	default:
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, storeOrganizationStoreError(apperror.KindBadRequest, "backend.identity.store_organization_operation_invalid")
	}

	now := nowString()
	result := identitymodel.IdentityStoreOrganizationDeliveryResult{
		DeliveryID:   handlerDeliveryStableID("store-organization", mutation.WorkspaceID, mutation.IdempotencyKey),
		Organization: storeOrganizationStoreProjection(mutation.Organization, currentVersion),
	}
	receipt := identitymodel.IdentityStoreOrganizationDeliveryReceipt{
		WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Result: result, CreatedAt: now,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, err
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_store_organization_deliveries", mutation.WorkspaceID).
		Columns("id", "actor_id", "idempotency_key", "request_fingerprint", "result_json", "created_at").
		Values(result.DeliveryID, mutation.ActorID, mutation.IdempotencyKey, mutation.RequestFingerprint, string(resultJSON), now).Build()
	if err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, fmt.Errorf("build Identity store organization receipt insert: %w", err)
	}
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return identitymodel.IdentityStoreOrganizationDeliveryReceipt{}, normalizeStoreOrganizationWriteError(err)
	}
	return receipt, nil
}

func (s *SQLIdentityStore) insertStoreOrganization(ctx context.Context, executor identitytransaction.Executor, workspaceID string, organization identitymodel.IdentityOrganizationUnit) error {
	ancestors, _ := json.Marshal(organization.AncestorIDs)
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Columns("id", "code", "name", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
		Values(organization.ID, organization.Code, organization.Name, string(identitymodel.IdentityOrganizationUnitStore), identityStoreOrganizationParentID(organization), organization.Path, string(ancestors), organization.Depth, organization.SortOrder, string(organization.Status), nowString(), nowString()).Build()
	if err != nil {
		return fmt.Errorf("build Identity store organization insert: %w", err)
	}
	_, err = executor.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) updateStoreOrganizationCAS(ctx context.Context, executor identitytransaction.Executor, workspaceID string, current, desired identitymodel.IdentityOrganizationUnit, operation identitymodel.IdentityStoreOrganizationOperation) (bool, error) {
	currentAncestors, _ := json.Marshal(current.AncestorIDs)
	predicates := []query.Predicate{
		query.Equal("id", current.ID), query.Equal("code", current.Code), query.Equal("name", current.Name),
		query.Equal("node_type", string(identitymodel.IdentityOrganizationUnitStore)), query.Equal("parent_id", identityStoreOrganizationParentID(current)),
		query.Equal("path", current.Path), query.Equal("ancestor_ids", string(currentAncestors)), query.Equal("depth", current.Depth),
		query.Equal("sort_order", current.SortOrder), query.Equal("status", string(current.Status)),
	}
	update := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).Set("updated_at", nowString())
	switch operation {
	case identitymodel.IdentityStoreOrganizationRename:
		update.Set("name", desired.Name)
	case identitymodel.IdentityStoreOrganizationDisable:
		update.Set("status", string(identitymodel.IdentityStatusDisabled))
	default:
		return false, storeOrganizationStoreError(apperror.KindBadRequest, "backend.identity.store_organization_operation_invalid")
	}
	statement, arguments, err := update.Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity store organization CAS update: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (s *SQLIdentityStore) insertStoreOrganizationState(ctx context.Context, executor identitytransaction.Executor, workspaceID, organizationID string, version int64, fingerprint string) error {
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_store_organization_states", workspaceID).
		Columns("id", "organization_id", "version", "state_fingerprint", "updated_at").
		Values(handlerDeliveryStableID("store-organization-state", workspaceID, organizationID), organizationID, version, fingerprint, nowString()).Build()
	if err != nil {
		return fmt.Errorf("build Identity store organization state insert: %w", err)
	}
	_, err = executor.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) updateStoreOrganizationStateCAS(ctx context.Context, executor identitytransaction.Executor, workspaceID, organizationID string, expectedVersion int64, expectedFingerprint string, nextVersion int64, nextFingerprint string) (bool, error) {
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_store_organization_states", workspaceID).
		Set("version", nextVersion).Set("state_fingerprint", nextFingerprint).Set("updated_at", nowString()).
		Where(query.And(query.Equal("organization_id", organizationID), query.Equal("version", expectedVersion), query.Equal("state_fingerprint", expectedFingerprint))).Build()
	if err != nil {
		return false, fmt.Errorf("build Identity store organization state CAS update: %w", err)
	}
	result, err := executor.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func storeOrganizationMutationScopeAllows(scope identitymodel.IdentityDataScopeFilter, operation identitymodel.IdentityStoreOrganizationOperation, organization identitymodel.IdentityOrganizationUnit) bool {
	if scope.Unrestricted {
		return true
	}
	target := organization.ID
	if operation == identitymodel.IdentityStoreOrganizationCreate {
		target = identityStoreOrganizationParentID(organization)
	}
	for _, allowed := range scope.Normalized().OwnerOrgIDs {
		if strings.TrimSpace(allowed) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
}

func identityStoreOrganizationParentID(organization identitymodel.IdentityOrganizationUnit) string {
	if organization.ParentID == nil {
		return ""
	}
	return strings.TrimSpace(*organization.ParentID)
}

func storeOrganizationStateFingerprint(organization identitymodel.IdentityOrganizationUnit) string {
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func storeOrganizationStoreProjection(organization identitymodel.IdentityOrganizationUnit, version int64) identitymodel.IdentityStoreOrganization {
	return identitymodel.IdentityStoreOrganization{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, Status: string(organization.Status),
		ParentOrganizationID: identityStoreOrganizationParentID(organization), Path: organization.Path,
		AncestorIDs: append([]string(nil), organization.AncestorIDs...), Depth: organization.Depth, SortOrder: organization.SortOrder, Version: version,
	}
}

func normalizeStoreOrganizationWriteError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		return storeOrganizationStoreError(apperror.KindConflict, "backend.identity.store_organization_conflict")
	}
	return err
}

func storeOrganizationStoreError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}

var _ identityrepository.IdentityStoreOrganizationDeliveryRepository = (*SQLIdentityStore)(nil)
