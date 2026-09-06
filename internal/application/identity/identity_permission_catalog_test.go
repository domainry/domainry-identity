package identity

import (
	"context"
	"slices"
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type permissionCatalogRepositoryStub struct {
	records []identitymodel.IdentityPermissionDefinitionRecord
}

func (repository *permissionCatalogRepositoryStub) ListIdentityPermissionDefinitions(context.Context, string) ([]identitymodel.IdentityPermissionDefinitionRecord, error) {
	return slices.Clone(repository.records), nil
}

func (repository *permissionCatalogRepositoryStub) GetIdentityPermissionDefinition(_ context.Context, _ string, key string) (identitymodel.IdentityPermissionDefinitionRecord, bool, error) {
	for _, record := range repository.records {
		if record.PermissionKey == key {
			return record, true, nil
		}
	}
	return identitymodel.IdentityPermissionDefinitionRecord{}, false, nil
}

func (repository *permissionCatalogRepositoryStub) SetIdentityPermissionDefinitionEnabled(_ context.Context, _ string, key string, enabled bool) (bool, error) {
	for index := range repository.records {
		if repository.records[index].PermissionKey == key && repository.records[index].DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive {
			changed := repository.records[index].Enabled != enabled
			repository.records[index].Enabled = enabled
			return changed, nil
		}
	}
	return false, nil
}

func (repository *permissionCatalogRepositoryStub) ReconcileIdentityPermissionDefinitions(_ context.Context, request identitymodel.IdentityPermissionReconcileRequest) (identitymodel.IdentityPermissionReconcileReceipt, error) {
	current := make(map[string]identitymodel.IdentityPermissionDefinitionRecord, len(repository.records))
	retained := make([]identitymodel.IdentityPermissionDefinitionRecord, 0, len(repository.records)+len(request.Definitions))
	for _, record := range repository.records {
		current[record.PermissionKey] = record
		if record.SourceOwner != request.SourceOwner {
			retained = append(retained, record)
		}
	}
	for _, definition := range request.Definitions {
		if existing, found := current[definition.PermissionKey]; found {
			definition.Enabled = existing.Enabled
		}
		retained = append(retained, definition)
	}
	repository.records = retained
	return identitymodel.IdentityPermissionReconcileReceipt{
		WorkspaceID: request.WorkspaceID, SourceOwner: request.SourceOwner,
		SnapshotHash: request.SnapshotHash, Inserted: len(request.Definitions),
	}, nil
}

func TestPermissionDefinitionAndSnapshotHashesAreCanonical(t *testing.T) {
	definition := identitymodel.IdentityPermissionDefinitionRecord{
		PermissionKey: "identity.roles.get", ResourceKey: "identity.roles", OperationKey: "get", Label: "Get role",
		Description: "Get one role", Category: "Identity", SourceKind: "builtin_http", SourceOwner: "identity:builtin",
	}
	first, err := IdentityPermissionDefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Enabled = false
	definition.ID = "database-row"
	definition.UpdatedAt = "later"
	second, err := IdentityPermissionDefinitionHash(definition)
	if err != nil || first != second {
		t.Fatalf("source hash changed with administrator/database fields: %q %q err=%v", first, second, err)
	}
	left := []identitymodel.IdentityPermissionDefinitionRecord{{PermissionKey: "b", DefinitionHash: "2"}, {PermissionKey: "a", DefinitionHash: "1"}}
	right := slices.Clone(left)
	slices.Reverse(right)
	leftHash, err := IdentityPermissionSourceSnapshotHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := IdentityPermissionSourceSnapshotHash(right)
	if err != nil || leftHash != rightHash {
		t.Fatalf("snapshot hash is order dependent: %q %q err=%v", leftHash, rightHash, err)
	}
}

func TestRolePermissionSelectionsRequireCurrentSelectableDefinitions(t *testing.T) {
	service := &IdentityPermissionCatalogApplicationService{}
	service.snapshot.Store(&identityPermissionRuntimeSnapshot{byKey: map[string]identityPermissionRuntimeState{
		"active":   {active: true, enabled: true},
		"disabled": {active: true, enabled: false},
		"retired":  {active: false, enabled: true},
	}})
	if err := service.ValidatePermissionSelections([]string{"active"}); err != nil {
		t.Fatalf("active permission rejected: %v", err)
	}
	for _, test := range []struct {
		key  string
		code string
	}{
		{key: "missing", code: "backend.identity.permission_not_found"},
		{key: "disabled", code: "backend.identity.permission_disabled"},
		{key: "retired", code: "backend.identity.permission_retired"},
	} {
		if err := service.ValidatePermissionSelections([]string{test.key}); apperror.CodeOf(err) != test.code {
			t.Fatalf("selection %q error=%v code=%q", test.key, err, apperror.CodeOf(err))
		}
	}
}

func TestPermissionReconcileEmitsStableReceiptLogWithGeneratedRequestID(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	service, err := NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	core, observed := observer.New(zap.InfoLevel)
	previous := zap.L()
	zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(func() { zap.ReplaceGlobals(previous) })
	receipt, err := service.ReconcileOwner(t.Context(), IdentityBuiltinAuthorizationOwner)
	if err != nil || receipt.Inserted != 95 {
		t.Fatalf("reconcile receipt=%+v error=%v", receipt, err)
	}
	entries := observed.FilterMessage("identity_permission_reconcile_applied").All()
	if len(entries) != 1 {
		t.Fatalf("reconcile log entries=%v", observed.All())
	}
	fields := entries[0].ContextMap()
	if fields["workspace_id"] != "workspace-primary" || fields["source_owner"] != IdentityBuiltinAuthorizationOwner || fields["snapshot_hash"] != receipt.SnapshotHash || fields["inserted"] != int64(95) {
		t.Fatalf("reconcile log fields=%v", fields)
	}
	requestID, _ := fields["request_id"].(string)
	if requestID == "" {
		t.Fatalf("reconcile log has no request id: %v", fields)
	}
}

func TestPermissionCatalogReconcilesExternalOwnerAndEnablementChangesSharedSnapshot(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	service, err := NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	definitions := []identitymodel.IdentityPermissionDefinitionRecord{{
		PermissionKey: "customer.read", ResourceKey: "customer", OperationKey: "read", Label: "Read customers",
		Category: "Customer", SourceKind: "object_default", SourceOwner: "runtime:orders",
	}}
	snapshotHash, err := identityPermissionSnapshotHash("runtime:orders", definitions)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.ReconcileDefinitions(t.Context(), "runtime:orders", "", snapshotHash, definitions)
	if err != nil {
		t.Fatal(err)
	}
	if !service.PermissionIsExecutable("customer.read") || !service.PermissionDefinitions()["customer.read"].Enabled {
		t.Fatalf("external definition was not loaded into the shared snapshot: %#v", service.PermissionDefinitions())
	}
	external := service.PermissionDefinitions()["customer.read"]
	if external.ActionUsageStatus != identitymodel.IdentityActionUsageUnavailable || len(external.ActionUsages) != 0 {
		t.Fatalf("unreachable external Action registry was presented as live: %#v", external)
	}
	result, err := service.SetEnabled(t.Context(), "customer.read", false)
	if err != nil || !result.Changed || result.Before != true || result.Enabled {
		t.Fatalf("enablement result=%+v err=%v", result, err)
	}
	if service.PermissionIsExecutable("customer.read") || service.PermissionDefinitions()["customer.read"].Enabled {
		t.Fatal("disabled permission remained executable in the shared snapshot")
	}
	if _, err := service.ReconcileDefinitions(t.Context(), "runtime:orders", receipt.SnapshotHash, snapshotHash, definitions); err != nil {
		t.Fatal(err)
	}
	if service.PermissionIsExecutable("customer.read") {
		t.Fatal("owner reconcile overwrote administrator enablement")
	}
	definitions[0].SourceOwner = "runtime:other"
	if _, err := service.ReconcileDefinitions(t.Context(), "runtime:orders", receipt.SnapshotHash, snapshotHash, definitions); err == nil {
		t.Fatal("external snapshot accepted a mismatched canonical owner")
	}
}

func TestPermissionCatalogMarksLocalRegistryUsageAvailable(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	service, err := NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileOwner(t.Context(), IdentityBuiltinAuthorizationOwner); err != nil {
		t.Fatal(err)
	}
	definition := service.PermissionDefinitions()["identity.roles.list"]
	if definition.ActionUsageStatus != identitymodel.IdentityActionUsageAvailable || len(definition.ActionUsages) != 1 {
		t.Fatalf("local Action usage projection=%#v", definition)
	}
}

func TestPermissionCatalogQueriesExternalActionUsageWithoutPersistingIt(t *testing.T) {
	identityRegistry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	service, err := NewIdentityPermissionCatalogApplicationService(repository, identityRegistry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	definitions := []identitymodel.IdentityPermissionDefinitionRecord{{
		PermissionKey: "customer.read", ResourceKey: "customer", OperationKey: "read", Label: "Read customers",
		Category: "Customer", SourceKind: "object_default", SourceOwner: "runtime:orders",
	}}
	snapshotHash, err := identityPermissionSnapshotHash("runtime:orders", definitions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileDefinitions(t.Context(), "runtime:orders", "", snapshotHash, definitions); err != nil {
		t.Fatal(err)
	}
	runtimeRegistry := actioncontract.NewRegistry()
	if err := runtimeRegistry.Register(actioncontract.ActionDefinition{
		Key: "customer.read", Owner: "runtime:orders", SourceKind: "object_default",
		CapabilityKey: "customer", CapabilityLabel: "Customers", OperationKey: "read", OperationLabel: "Read",
		Label: "Read customers", Exposures: []actioncontract.Exposure{actioncontract.ExposureManagement},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
		HTTP:          &actioncontract.HTTPBinding{Method: "GET", RouteTemplate: "/objects/customer/records"},
		Permission: &actioncontract.PermissionDefinition{
			Key: "customer.read", Owner: "runtime:orders", ResourceKey: "customer", OperationKey: "read",
			Label: "Read customers", Category: "Customers", LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: actioncontract.EffectRead, RiskLevel: actioncontract.RiskLow,
		IdempotencyDecision: "not_applicable", AuditClass: "business_read", LifecycleStatus: actioncontract.LifecycleActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtimeRegistry.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := service.UseActionUsageProvider(runtimeRegistry); err != nil {
		t.Fatal(err)
	}

	listed, err := service.List(t.Context())
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	if listed[0].ActionUsageStatus != identitymodel.IdentityActionUsageAvailable || len(listed[0].ActionUsages) != 1 || listed[0].ActionUsages[0].ActionKey != "customer.read" || listed[0].ActionUsages[0].RouteTemplate != "/objects/customer/records" {
		t.Fatalf("external usage=%#v", listed[0])
	}
	stored, found, err := repository.GetIdentityPermissionDefinition(t.Context(), "workspace", "customer.read")
	if err != nil || !found || stored.PermissionKey != "customer.read" {
		t.Fatalf("stored definition=%#v found=%t err=%v", stored, found, err)
	}
	if current := service.PermissionDefinitions()["customer.read"]; current.ActionUsageStatus != identitymodel.IdentityActionUsageUnavailable || len(current.ActionUsages) != 0 {
		t.Fatalf("live usage leaked into current permission state: %#v", current)
	}
}

func TestPermissionCatalogProtectsOnlyPermissionRecoveryActionFromAdministrativeDisable(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	service, err := NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileOwner(t.Context(), IdentityBuiltinAuthorizationOwner); err != nil {
		t.Fatal(err)
	}
	if result, err := service.SetEnabled(t.Context(), "identity.permissions.list", false); err != nil || !result.Changed || result.Enabled {
		t.Fatalf("ordinary exact Permission disable result=%+v err=%v", result, err)
	}
	if _, err := service.SetEnabled(t.Context(), "identity.permissions.set_enabled", false); apperror.CodeOf(err) != "backend.identity.permission_recovery_capability_required" {
		t.Fatalf("permission recovery Action disable err=%v", err)
	}
}
