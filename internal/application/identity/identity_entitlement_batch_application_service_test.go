package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type entitlementBatchFaultRepository struct {
	*identityScopedRepository
	receiptErr error
}

func (r *entitlementBatchFaultRepository) GetIdentityEntitlementBatchReceipt(context.Context, string, string) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return identitymodel.IdentityEntitlementBatchReceipt{}, false, r.receiptErr
}

func (r *entitlementBatchFaultRepository) GetIdentityEntitlementBatchReceiptWithinDataScope(context.Context, string, string, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityEntitlementBatchReceipt, bool, error) {
	return identitymodel.IdentityEntitlementBatchReceipt{}, false, r.receiptErr
}

func TestApplyEntitlementBatchValidatesThenPersistsAndReplaysReceipt(t *testing.T) {
	repository := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{
			{ID: "role-1", Key: "reader", Status: identitymodel.IdentityStatusActive},
			{ID: "role-2", Key: "writer", Status: identitymodel.IdentityStatusActive},
		},
	}
	service := NewIdentityApplicationService(repository, nil)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "reader", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "writer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace")
	actor := identityAllowAllRoleAssignments(identitymodel.Principal{Known: true, UserID: "grant-admin", WorkspaceID: "workspace"})
	request := IdentityEntitlementBatchRequest{
		IdempotencyKey: "batch-1",
		Items: []identitymodel.IdentityEntitlementBatchItem{
			{Operation: "grant", UserID: "target", RoleID: "role-2", Reason: "job"},
			{Operation: "grant", UserID: "target", RoleID: "role-1", Reason: "job"},
		},
	}
	receipt, err := service.ApplyEntitlementBatch(ctx, request, actor)
	if err != nil || receipt.Replayed || len(repository.assignments) != 2 {
		t.Fatalf("receipt=%#v assignments=%#v err=%v", receipt, repository.assignments, err)
	}
	reordered := request
	reordered.Items = []identitymodel.IdentityEntitlementBatchItem{request.Items[1], request.Items[0]}
	replay, err := service.ApplyEntitlementBatch(ctx, reordered, actor)
	if err != nil || !replay.Replayed || len(repository.assignments) != 2 {
		t.Fatalf("replay=%#v assignments=%#v err=%v", replay, repository.assignments, err)
	}
	reused := request
	reused.Items[0].Reason = "different"
	if _, err := service.ApplyEntitlementBatch(ctx, reused, actor); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("reused key error=%v", err)
	}
}

func TestApplyEntitlementBatchRejectsInvalidBoundariesAndPropagatesFailures(t *testing.T) {
	base := &identityScopedRepository{
		users: []identitymodel.IdentityUser{{ID: "target", Status: identitymodel.IdentityStatusActive}},
		roles: []identitymodel.IdentityRole{{ID: "role", Key: "reader", Status: identitymodel.IdentityStatusActive}},
	}
	service := NewIdentityApplicationService(base, nil)
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{Key: "reader", AssignmentMode: identitymodel.IdentityRoleAssignmentManual}})
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace")
	actor := identityAllowAllRoleAssignments(identitymodel.Principal{Known: true, UserID: "actor", WorkspaceID: "workspace"})
	valid := IdentityEntitlementBatchRequest{
		IdempotencyKey: "key",
		Items:          []identitymodel.IdentityEntitlementBatchItem{{Operation: "grant", UserID: "target", RoleID: "role", Reason: "needed"}},
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.ApplyEntitlementBatch(canceled, valid, actor); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error=%v", err)
	}
	unknown := actor
	unknown.Known = false
	if _, err := service.ApplyEntitlementBatch(ctx, valid, unknown); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("unknown actor error=%v", err)
	}
	noID := actor
	noID.UserID = " "
	if _, err := service.ApplyEntitlementBatch(ctx, valid, noID); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
		t.Fatalf("blank actor error=%v", err)
	}
	for _, request := range []IdentityEntitlementBatchRequest{
		{Items: valid.Items},
		{IdempotencyKey: "key"},
	} {
		if _, err := service.ApplyEntitlementBatch(ctx, request, actor); apperror.CodeOf(err) != "backend.identity.entitlement_batch_invalid" {
			t.Fatalf("invalid request=%#v err=%v", request, err)
		}
	}
	if _, err := service.ApplyEntitlementBatch(t.Context(), valid, actor); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("missing workspace context error=%v", err)
	}
	unavailable := NewIdentityApplicationService(&accessReviewUnavailableRepository{}, nil)
	if _, err := unavailable.ApplyEntitlementBatch(ctx, valid, actor); apperror.CodeOf(err) != "backend.identity.entitlement_batch_unavailable" {
		t.Fatalf("unavailable repository error=%v", err)
	}
	receiptErr := errors.New("receipt")
	fault := &entitlementBatchFaultRepository{identityScopedRepository: base, receiptErr: receiptErr}
	faultService := NewIdentityApplicationService(fault, nil)
	if _, err := faultService.ApplyEntitlementBatch(ctx, valid, actor); !errors.Is(err, receiptErr) {
		t.Fatalf("receipt lookup error=%v", err)
	}
	invalidItem := valid
	invalidItem.IdempotencyKey = "invalid-item"
	invalidItem.Items = []identitymodel.IdentityEntitlementBatchItem{{Operation: "grant", UserID: "missing", RoleID: "role"}}
	if _, err := service.ApplyEntitlementBatch(ctx, invalidItem, actor); err == nil {
		t.Fatal("invalid entitlement item was accepted")
	}
}
