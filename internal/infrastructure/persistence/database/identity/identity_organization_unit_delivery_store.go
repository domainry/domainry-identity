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
	if result.DeliveryID != operation.ID || result.Organization.ID != operation.ResourceID {
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
		Columns("id", "delivery_version", "delivery_state_fingerprint", "updated_at").
		Where(query.And(query.Equal("id", strings.TrimSpace(organizationID)), query.Equal("delivery_owner", organizationUnitStateOwner))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, fmt.Errorf("build Identity organization unit delivery state query: %w", err)
	}
	var state identitymodel.IdentityOrganizationUnitDeliveryState
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&state.OrganizationID, &state.Version, &state.StateFingerprint, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, err
	}
	state.WorkspaceID = workspaceID
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
	childID := query.QualifiedColumn("child", "id")
	parentID := query.QualifiedColumn("parent", "id")
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
			query.Project(childID), query.Project(query.QualifiedColumn("child", "code")), query.Project(query.QualifiedColumn("child", "name")),
			query.Project(query.QualifiedColumn("child", "node_type")), query.Project(query.QualifiedColumn("child", "status")), query.Project(parentID),
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
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(
		&item.ID, &item.Code, &item.Name, &item.NodeType, &item.Status, &item.ParentOrganizationID,
		&item.Path, &ancestorsJSON, &item.Depth, &item.SortOrder, &item.Version, &stateFingerprint,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityDeliveredOrganizationUnit{}, false, err
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

func (s *SQLIdentityStore) ExecuteIdentityOrganizationUnitDelivery(ctx context.Context, mutation identitymodel.IdentityOrganizationUnitDeliveryMutation) (identitymodel.IdentityOrganizationUnitDeliveryReceipt, error) {
	executor := identitytransaction.ExecutorFromContext(ctx)
	if executor == nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindInternal, "backend.identity.organization_unit_transaction_required")
	}
	parentID := identityOrganizationUnitDeliveryParentID(mutation.Organization.ParentID)
	if strings.TrimSpace(mutation.WorkspaceID) == "" || strings.TrimSpace(mutation.ActorID) == "" || strings.TrimSpace(mutation.IdempotencyKey) == "" || strings.TrimSpace(mutation.RequestFingerprint) == "" || strings.TrimSpace(mutation.Organization.ID) == "" || parentID == "" || mutation.ExpectedVersion != 0 || !validOrganizationUnitDeliveryNodeType(mutation.Organization.NodeType) {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindBadRequest, "backend.identity.organization_unit_delivery_invalid")
	}
	if !s.OperationsPersistenceBound() {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	if !organizationUnitDeliveryMutationScopeAllows(mutation.DataScope, parentID) {
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
	// A same-parent concurrent invocation may have committed while this
	// transaction waited for the parent lock. Re-read the receipt so an
	// identical request replays instead of degrading into an ID conflict.
	if receipt, receiptFound, receiptErr := s.GetIdentityOrganizationUnitDeliveryReceipt(ctx, mutation.WorkspaceID, mutation.IdempotencyKey); receiptErr != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, receiptErr
	} else if receiptFound {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Result.Replayed = true
		return receipt, nil
	}
	if _, found, err := s.GetIdentityOrganizationUnitWithinDataScope(ctx, mutation.WorkspaceID, mutation.Organization.ID, identitymodel.IdentityDataScopeFilter{Unrestricted: true}); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
	} else if found {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, organizationUnitDeliveryStoreError(apperror.KindConflict, "backend.identity.organization_unit_version_conflict")
	}
	if err := s.insertDeliveredOrganizationUnit(ctx, executor, mutation.WorkspaceID, mutation.Organization, 1, organizationUnitDeliveryStoreFingerprint(mutation.Organization)); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, normalizeOrganizationUnitDeliveryWriteError(err)
	}

	now := nowString()
	result := identitymodel.IdentityOrganizationUnitDeliveryResult{
		DeliveryID:   handlerDeliveryStableID("organization-unit", mutation.WorkspaceID, mutation.IdempotencyKey),
		Organization: identityOrganizationUnitDeliveryStoreProjection(mutation.Organization, 1),
	}
	receipt := identitymodel.IdentityOrganizationUnitDeliveryReceipt{
		WorkspaceID: mutation.WorkspaceID, ActorID: mutation.ActorID, IdempotencyKey: mutation.IdempotencyKey,
		RequestFingerprint: mutation.RequestFingerprint, Result: result, CreatedAt: now,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, err
	}
	relatedIDsJSON, _ := json.Marshal(uniqueHandlerDeliveryStrings([]string{mutation.Organization.ID, parentID}))
	if err := operationreceipt.InsertSucceeded(ctx, executor, s.sqlRenderer(), operationreceipt.Succeeded{
		ID: result.DeliveryID, WorkspaceID: mutation.WorkspaceID, Owner: organizationUnitOperationOwner, Kind: organizationUnitOperationKind,
		ActionKey: "identity.organization_unit.create", ResourceType: "identity_organization_unit", ResourceID: mutation.Organization.ID,
		IdempotencyKey: mutation.IdempotencyKey, RequestFingerprint: mutation.RequestFingerprint, RequestedBy: mutation.ActorID,
		Reason: "deliver organization unit", ResultJSON: resultJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: now,
	}); err != nil {
		return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, normalizeOrganizationUnitDeliveryWriteError(err)
	}
	return receipt, nil
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
		Where(query.Equal("id", strings.TrimSpace(parentID))).Build()
}

func identityOrganizationUnitDeliveryHierarchyMatchesParent(organization, parent identitymodel.IdentityOrganizationUnit) bool {
	if identityOrganizationUnitDeliveryParentID(organization.ParentID) != strings.TrimSpace(parent.ID) || organization.ID == parent.ID {
		return false
	}
	expectedAncestors := append(append([]string(nil), parent.AncestorIDs...), parent.ID)
	if organization.Depth != len(expectedAncestors) || organization.Path != strings.TrimRight(parent.Path, "/")+"/"+organization.ID || len(organization.AncestorIDs) != len(expectedAncestors) {
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
		Columns("id", "code", "name", "sibling_key", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "delivery_owner", "delivery_version", "delivery_state_fingerprint", "created_at", "updated_at").
		Values(organization.ID, organization.Code, organization.Name, identitymodel.IdentityOrganizationUnitSiblingKey(organization.ParentID, organization.Name), string(organization.NodeType), identityOrganizationUnitDeliveryParentID(organization.ParentID), organization.Path, string(ancestors), organization.Depth, organization.SortOrder, string(organization.Status), organizationUnitStateOwner, version, fingerprint, nowString(), nowString()).Build()
	if err != nil {
		return fmt.Errorf("build Identity organization unit delivery insert: %w", err)
	}
	_, err = executor.ExecContext(ctx, statement, arguments...)
	return err
}

func validOrganizationUnitDeliveryNodeType(nodeType identitymodel.IdentityOrganizationUnitType) bool {
	switch nodeType {
	case identitymodel.IdentityOrganizationUnitRegion, identitymodel.IdentityOrganizationUnitDepartment, identitymodel.IdentityOrganizationUnitTeam, identitymodel.IdentityOrganizationUnitWarehouse:
		return true
	default:
		return false
	}
}

func validOrganizationUnitDeliveryParentTypePredicate() query.Predicate {
	values := []any{
		string(identitymodel.IdentityOrganizationUnitCompany), string(identitymodel.IdentityOrganizationUnitRegion),
		string(identitymodel.IdentityOrganizationUnitStore), string(identitymodel.IdentityOrganizationUnitDepartment),
		string(identitymodel.IdentityOrganizationUnitTeam), string(identitymodel.IdentityOrganizationUnitWarehouse),
	}
	return query.InExpression(query.QualifiedColumn("parent", "node_type"), values...)
}

func organizationUnitDeliveryMutationScopeAllows(scope identitymodel.IdentityDataScopeFilter, parentID string) bool {
	if scope.Unrestricted {
		return true
	}
	parentID = strings.TrimSpace(parentID)
	for _, allowed := range scope.Normalized().OwnerOrgIDs {
		if allowed == parentID {
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
	payload, _ := json.Marshal(organization)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func deliveredOrganizationUnitStoreFingerprint(organization identitymodel.IdentityDeliveredOrganizationUnit) string {
	parentID := organization.ParentOrganizationID
	return organizationUnitDeliveryStoreFingerprint(identitymodel.IdentityOrganizationUnit{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
		ParentID: &parentID, Path: organization.Path, AncestorIDs: append([]string(nil), organization.AncestorIDs...),
		Depth: organization.Depth, SortOrder: organization.SortOrder, Status: identitymodel.IdentityStatus(organization.Status),
	})
}

func identityOrganizationUnitDeliveryStoreProjection(organization identitymodel.IdentityOrganizationUnit, version int64) identitymodel.IdentityDeliveredOrganizationUnit {
	return identitymodel.IdentityDeliveredOrganizationUnit{
		ID: organization.ID, Code: organization.Code, Name: organization.Name, NodeType: organization.NodeType,
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
