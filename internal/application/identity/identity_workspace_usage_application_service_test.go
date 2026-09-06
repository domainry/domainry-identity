package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type workspaceUsageAuthorityStub struct {
	grant        identitymodel.IdentityWorkspaceUsageGrant
	entries      []identitymodel.IdentityWorkspaceUsageCatalogEntry
	page         *identitymodel.IdentityWorkspaceUsageCatalogPage
	authorizeErr error
	listErr      error
	resolveErr   error
	permissions  []string
	queries      []workspaceUsageCatalogQuery
}

func (stub *workspaceUsageAuthorityStub) ResolveAuthorizedWorkspaceIdentityUsage(_ context.Context, _ identitymodel.IdentityWorkspaceUsageGrant, workspaceCode string) (identitymodel.IdentityWorkspaceUsageCatalogEntry, error) {
	if stub.resolveErr != nil {
		return identitymodel.IdentityWorkspaceUsageCatalogEntry{}, stub.resolveErr
	}
	if workspaceCode == "night-tokyo" && len(stub.entries) > 0 {
		return stub.entries[0], nil
	}
	return identitymodel.IdentityWorkspaceUsageCatalogEntry{}, nil
}

type workspaceUsageCatalogQuery struct {
	after            string
	limit            int
	expectedRevision string
}

func (stub *workspaceUsageAuthorityStub) AuthorizeWorkspaceIdentityUsage(_ context.Context, _ string, permissionKey string) (identitymodel.IdentityWorkspaceUsageGrant, error) {
	stub.permissions = append(stub.permissions, permissionKey)
	return stub.grant, stub.authorizeErr
}

func (stub *workspaceUsageAuthorityStub) ListAuthorizedWorkspaceIdentityUsage(_ context.Context, _ identitymodel.IdentityWorkspaceUsageGrant, after string, limit int, expectedRevision string) (identitymodel.IdentityWorkspaceUsageCatalogPage, error) {
	stub.queries = append(stub.queries, workspaceUsageCatalogQuery{after: after, limit: limit, expectedRevision: expectedRevision})
	if stub.listErr != nil {
		return identitymodel.IdentityWorkspaceUsageCatalogPage{}, stub.listErr
	}
	if stub.page != nil {
		return *stub.page, nil
	}
	page := identitymodel.IdentityWorkspaceUsageCatalogPage{CatalogRevision: "catalog-1"}
	for _, entry := range stub.entries {
		if entry.WorkspaceID > after {
			page.Workspaces = append(page.Workspaces, entry)
		}
		if len(page.Workspaces) == limit {
			break
		}
	}
	return page, nil
}

type workspaceUsageRepositoryStub struct {
	groups           []identitymodel.IdentityWorkspaceUsageGroup
	activeRoleCounts []identitymodel.IdentityWorkspaceActiveHumanRoleCount
	err              error
	activeRoleErr    error
	workspaceCalls   [][]string
	activeRoleCalls  [][]string
}

func (stub *workspaceUsageRepositoryStub) CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(_ context.Context, workspaceIDs []string) ([]identitymodel.IdentityWorkspaceActiveHumanRoleCount, error) {
	stub.activeRoleCalls = append(stub.activeRoleCalls, append([]string(nil), workspaceIDs...))
	allowed := make(map[string]struct{}, len(workspaceIDs))
	for _, workspaceID := range workspaceIDs {
		allowed[workspaceID] = struct{}{}
	}
	var counts []identitymodel.IdentityWorkspaceActiveHumanRoleCount
	for _, count := range stub.activeRoleCounts {
		if _, ok := allowed[count.WorkspaceID]; ok {
			counts = append(counts, count)
		}
	}
	return counts, stub.activeRoleErr
}

func (stub *workspaceUsageRepositoryStub) CountIdentityWorkspaceUsage(_ context.Context, workspaceIDs []string) ([]identitymodel.IdentityWorkspaceUsageGroup, error) {
	stub.workspaceCalls = append(stub.workspaceCalls, append([]string(nil), workspaceIDs...))
	allowed := make(map[string]struct{}, len(workspaceIDs))
	for _, workspaceID := range workspaceIDs {
		allowed[workspaceID] = struct{}{}
	}
	var groups []identitymodel.IdentityWorkspaceUsageGroup
	for _, group := range stub.groups {
		if _, ok := allowed[group.WorkspaceID]; ok {
			groups = append(groups, group)
		}
	}
	return groups, stub.err
}

type workspaceUsageAuditStub struct {
	err      error
	requests []auditapplication.AuditAppendRequest
}

func (stub *workspaceUsageAuditStub) AppendAudit(_ context.Context, request auditapplication.AuditAppendRequest) error {
	stub.requests = append(stub.requests, request)
	return stub.err
}

func workspaceUsageGrant() identitymodel.IdentityWorkspaceUsageGrant {
	return identitymodel.IdentityWorkspaceUsageGrant{
		InstallationID: "installation-1", ApplicationKey: "nightpos", SubjectID: "billing-service",
		AuditWorkspaceID: "workspace-audit", PermissionKey: IdentityWorkspaceUsageAggregatePermission, AuthorizationRevision: "auth-7",
		AuthorizationAuditID: "authority-audit-1",
	}
}

func activeWorkspaceUsageEntry(workspaceID string) identitymodel.IdentityWorkspaceUsageCatalogEntry {
	return identitymodel.IdentityWorkspaceUsageCatalogEntry{WorkspaceID: workspaceID, Status: "active", Known: true, Authorized: true}
}

func newWorkspaceUsageService(authority *workspaceUsageAuthorityStub, repository *workspaceUsageRepositoryStub, audit *workspaceUsageAuditStub) *IdentityWorkspaceUsageApplicationService {
	return newWorkspaceUsageServiceWithKey(authority, repository, audit, workspaceUsageCursorKey)
}

var workspaceUsageCursorKey = []byte("0123456789abcdef0123456789abcdef")

func newWorkspaceUsageServiceWithKey(authority *workspaceUsageAuthorityStub, repository *workspaceUsageRepositoryStub, audit *workspaceUsageAuditStub, cursorKey []byte) *IdentityWorkspaceUsageApplicationService {
	return NewIdentityWorkspaceUsageApplicationService(IdentityWorkspaceUsageDependencies{
		ApplicationKey: "nightpos", Authority: authority, Repository: repository, Audit: audit, CursorKey: cursorKey,
	})
}

func TestWorkspaceIdentityUsageUsesTrustedKeysetCatalogAndGroupedCounts(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{
		grant: workspaceUsageGrant(),
		entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{
			activeWorkspaceUsageEntry("workspace-a"), activeWorkspaceUsageEntry("workspace-b"), activeWorkspaceUsageEntry("workspace-c"),
		},
	}
	repository := &workspaceUsageRepositoryStub{groups: []identitymodel.IdentityWorkspaceUsageGroup{
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 2},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusDisabled, Count: 1},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusDeleted, Count: 9},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountService, Status: identitymodel.IdentityStatusActive, Count: 3},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountService, Status: identitymodel.IdentityStatusDisabled, Count: 2},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountAutomation, Status: identitymodel.IdentityStatusActive, Count: 4},
		{WorkspaceID: "workspace-b", AccountType: identitymodel.IdentityAccountAutomation, Status: identitymodel.IdentityStatusDisabled, Count: 1},
		{WorkspaceID: "workspace-c", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 8},
	}, activeRoleCounts: []identitymodel.IdentityWorkspaceActiveHumanRoleCount{
		{WorkspaceID: "workspace-a", Count: 1},
		{WorkspaceID: "workspace-c", Count: 4},
	}}
	audit := &workspaceUsageAuditStub{}
	service := newWorkspaceUsageService(authority, repository, audit)
	first, err := service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "installation-token", PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page=%+v", first)
	}
	if got := first.Items[0].Accounts; got.ActiveHumanAccounts != 2 || got.ActiveHumanAccountsWithActiveRole != 1 || got.DisabledHumanAccounts != 1 || got.ServiceAccounts != 5 || got.AutomationAccounts != 4 {
		t.Fatalf("workspace-a counts=%+v", got)
	}
	if got := first.Items[1].Accounts; got.ActiveHumanAccounts != 0 || got.AutomationAccounts != 1 {
		t.Fatalf("workspace-b counts=%+v", got)
	}
	if !reflect.DeepEqual(repository.workspaceCalls, [][]string{{"workspace-a", "workspace-b"}}) {
		t.Fatalf("aggregate queries=%v", repository.workspaceCalls)
	}
	if !reflect.DeepEqual(repository.activeRoleCalls, [][]string{{"workspace-a", "workspace-b"}}) {
		t.Fatalf("active human role aggregate queries=%v", repository.activeRoleCalls)
	}
	if len(authority.permissions) != 1 || authority.permissions[0] != IdentityWorkspaceUsageAggregatePermission || len(authority.queries) != 1 || authority.queries[0].limit != 3 {
		t.Fatalf("authority calls permissions=%v queries=%+v", authority.permissions, authority.queries)
	}
	if len(audit.requests) != 1 || !audit.requests[0].Principal.SystemScope.Valid() || audit.requests[0].Principal.WorkspaceID != "workspace-audit" || audit.requests[0].Principal.UserID != "billing-service" {
		t.Fatalf("audit requests=%+v", audit.requests)
	}
	if audit.requests[0].Metadata["authority_audit_id"] != "authority-audit-1" || audit.requests[0].Before != nil || audit.requests[0].After != nil {
		t.Fatalf("success audit is not linked/minimal: %+v", audit.requests[0])
	}

	second, err := service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "installation-token", PageSize: 2, Cursor: first.NextCursor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].WorkspaceID != "workspace-c" || second.Items[0].Accounts.ActiveHumanAccounts != 8 || second.Items[0].Accounts.ActiveHumanAccountsWithActiveRole != 4 || second.NextCursor != "" {
		t.Fatalf("second page=%+v", second)
	}
	if len(authority.queries) != 2 || authority.queries[1].after != "workspace-b" || authority.queries[1].expectedRevision != "catalog-1" {
		t.Fatalf("second catalog query=%+v", authority.queries)
	}
}

func TestWorkspaceIdentityUsageResolveCountsOnlyExactAuthoritySelectedWorkspace(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{
		activeWorkspaceUsageEntry("workspace-a"), activeWorkspaceUsageEntry("workspace-b"),
	}}
	repository := &workspaceUsageRepositoryStub{
		groups: []identitymodel.IdentityWorkspaceUsageGroup{
			{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 4},
			{WorkspaceID: "workspace-b", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 99},
		},
		activeRoleCounts: []identitymodel.IdentityWorkspaceActiveHumanRoleCount{{WorkspaceID: "workspace-a", Count: 3}, {WorkspaceID: "workspace-b", Count: 99}},
	}
	audit := &workspaceUsageAuditStub{}
	result, err := newWorkspaceUsageService(authority, repository, audit).Resolve(t.Context(), IdentityWorkspaceUsageResolveRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV3,
		ContractHash:    IdentityWorkspaceUsageContractHashV3,
		AccessToken:     "installation-token",
		WorkspaceCode:   "night-tokyo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkspaceID != "workspace-a" || result.Accounts.ActiveHumanAccounts != 4 || result.Accounts.ActiveHumanAccountsWithActiveRole != 3 ||
		len(repository.workspaceCalls) != 1 || !reflect.DeepEqual(repository.workspaceCalls[0], []string{"workspace-a"}) ||
		len(repository.activeRoleCalls) != 1 || !reflect.DeepEqual(repository.activeRoleCalls[0], []string{"workspace-a"}) {
		t.Fatalf("result=%#v repository=%#v", result, repository)
	}
	if len(audit.requests) != 1 || audit.requests[0].Event != "identity.workspace_identity_usage.resolve" || audit.requests[0].Metadata["authority_audit_id"] != "authority-audit-1" {
		t.Fatalf("audits=%#v", audit.requests)
	}
}

func TestWorkspaceIdentityUsageResolveRejectsUntrustedOrInactiveExactScopeBeforeCounting(t *testing.T) {
	for name, entry := range map[string]identitymodel.IdentityWorkspaceUsageCatalogEntry{
		"unknown":      {WorkspaceID: "workspace-a", Status: "active", Known: false, Authorized: true},
		"unauthorized": {WorkspaceID: "workspace-a", Status: "active", Known: true, Authorized: false},
		"inactive":     {WorkspaceID: "workspace-a", Status: "inactive", Known: true, Authorized: true},
	} {
		t.Run(name, func(t *testing.T) {
			authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{entry}}
			repository := &workspaceUsageRepositoryStub{}
			_, err := newWorkspaceUsageService(authority, repository, &workspaceUsageAuditStub{}).Resolve(t.Context(), IdentityWorkspaceUsageResolveRequest{
				ContractVersion: IdentityWorkspaceUsageContractVersionV3, ContractHash: IdentityWorkspaceUsageContractHashV3,
				AccessToken: "installation-token", WorkspaceCode: "night-tokyo",
			})
			if apperror.CodeOf(err) != "backend.identity.workspace_usage_catalog_scope_invalid" || len(repository.workspaceCalls) != 0 {
				t.Fatalf("error=%v calls=%#v", err, repository.workspaceCalls)
			}
		})
	}
}

func TestWorkspaceIdentityUsageRejectsUntrustedCatalogEntriesBeforeQuery(t *testing.T) {
	tests := []struct {
		name    string
		entries []identitymodel.IdentityWorkspaceUsageCatalogEntry
	}{
		{name: "inactive", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{{WorkspaceID: "workspace-a", Status: "inactive", Known: true, Authorized: true}}},
		{name: "unknown status", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{{WorkspaceID: "workspace-a", Status: "unknown", Known: true, Authorized: true}}},
		{name: "unauthorized", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{{WorkspaceID: "workspace-a", Status: "active", Known: true, Authorized: false}}},
		{name: "unknown Workspace", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{{WorkspaceID: "workspace-unknown", Status: "active", Known: false, Authorized: true}}},
		{name: "blank id", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{{WorkspaceID: "", Status: "active", Known: true, Authorized: true}}},
		{name: "unordered", entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-b"), activeWorkspaceUsageEntry("workspace-a")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			page := identitymodel.IdentityWorkspaceUsageCatalogPage{CatalogRevision: "catalog-1", Workspaces: test.entries}
			authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), page: &page}
			repository, audit := &workspaceUsageRepositoryStub{}, &workspaceUsageAuditStub{}
			_, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
				ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 2,
			})
			if err == nil || len(repository.workspaceCalls) != 0 || len(audit.requests) != 0 {
				t.Fatalf("err=%v repository=%v audit=%v", err, repository.workspaceCalls, audit.requests)
			}
		})
	}
}

func TestWorkspaceIdentityUsageFailsClosedForAuthorityLimitsAndAggregateDimensions(t *testing.T) {
	authorityError := errors.New("installation permission denied")
	authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), authorizeErr: authorityError}
	repository, audit := &workspaceUsageRepositoryStub{}, &workspaceUsageAuditStub{}
	if _, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token",
	}); !errors.Is(err, authorityError) || len(repository.workspaceCalls) != 0 {
		t.Fatalf("authority error=%v queries=%v", err, repository.workspaceCalls)
	}
	grantWithoutAudit := workspaceUsageGrant()
	grantWithoutAudit.AuthorizationAuditID = ""
	authority = &workspaceUsageAuthorityStub{grant: grantWithoutAudit, entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-a")}}
	if _, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token",
	}); apperror.CodeOf(err) != "backend.identity.workspace_usage_authority_invalid" || len(repository.workspaceCalls) != 0 {
		t.Fatalf("missing authority audit receipt err=%v queries=%v", err, repository.workspaceCalls)
	}

	authority = &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-a")}}
	service := newWorkspaceUsageService(authority, repository, audit)
	for _, pageSize := range []int{-1, IdentityWorkspaceUsageMaxPageSize + 1} {
		if _, err := service.List(t.Context(), IdentityWorkspaceUsageRequest{ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: pageSize}); apperror.CodeOf(err) != "backend.identity.workspace_usage_page_size_invalid" {
			t.Fatalf("page size %d error=%v", pageSize, err)
		}
	}

	for _, group := range []identitymodel.IdentityWorkspaceUsageGroup{
		{WorkspaceID: "workspace-a", AccountType: "unknown", Status: identitymodel.IdentityStatusActive, Count: 1},
		{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: "pending", Count: 1},
	} {
		t.Run(string(group.AccountType)+string(group.Status)+group.WorkspaceID, func(t *testing.T) {
			repo := &workspaceUsageRepositoryStub{groups: []identitymodel.IdentityWorkspaceUsageGroup{group}}
			_, err := newWorkspaceUsageService(authority, repo, &workspaceUsageAuditStub{}).List(t.Context(), IdentityWorkspaceUsageRequest{
				ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
			})
			if err == nil {
				t.Fatal("invalid aggregate dimension accepted")
			}
		})
	}
	repo := &workspaceUsageRepositoryStub{
		groups:           []identitymodel.IdentityWorkspaceUsageGroup{{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 1}},
		activeRoleCounts: []identitymodel.IdentityWorkspaceActiveHumanRoleCount{{WorkspaceID: "workspace-a", Count: 2}},
	}
	if _, err := newWorkspaceUsageService(authority, repo, &workspaceUsageAuditStub{}).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	}); apperror.CodeOf(err) != "backend.identity.workspace_usage_aggregate_invalid" {
		t.Fatalf("active role count exceeding active human accounts err=%v", err)
	}
}

func TestWorkspaceIdentityUsageRequiresCurrentContractVersionAndHash(t *testing.T) {
	for _, request := range []IdentityWorkspaceUsageRequest{
		{ContractVersion: IdentityWorkspaceUsageContractVersionV1, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token"},
		{ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: "stale-hash", AccessToken: "token"},
		{ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2},
	} {
		authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant()}
		_, err := newWorkspaceUsageService(authority, &workspaceUsageRepositoryStub{}, &workspaceUsageAuditStub{}).List(t.Context(), request)
		if apperror.CodeOf(err) != "backend.identity.workspace_usage_request_invalid" || len(authority.permissions) != 0 {
			t.Fatalf("request=%+v err=%v authority_calls=%d", request, err, len(authority.permissions))
		}
	}
}

func TestWorkspaceIdentityUsageAuditFailureReturnsNoResultAndReadsAreNotReplayCached(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-a")}}
	repository := &workspaceUsageRepositoryStub{groups: []identitymodel.IdentityWorkspaceUsageGroup{{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 1}}}
	auditFailure := errors.New("audit unavailable")
	audit := &workspaceUsageAuditStub{err: auditFailure}
	result, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	})
	if !errors.Is(err, auditFailure) || len(result.Items) != 0 {
		t.Fatalf("audit failure result=%+v err=%v", result, err)
	}

	audit.err = nil
	first, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	repository.groups[0].Count = 2
	// A reconstructed service models restart: current usage is intentionally
	// re-read and each successful read receives a new audit event.
	second, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Items[0].Accounts.ActiveHumanAccounts != 1 || second.Items[0].Accounts.ActiveHumanAccounts != 2 || len(audit.requests) != 3 {
		t.Fatalf("first=%+v second=%+v audits=%d", first, second, len(audit.requests))
	}
}

func TestWorkspaceIdentityUsageCursorCannotMixAuthorizationOrCatalogRevisions(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{
		grant: workspaceUsageGrant(),
		entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{
			activeWorkspaceUsageEntry("workspace-a"), activeWorkspaceUsageEntry("workspace-b"),
		},
	}
	repository := &workspaceUsageRepositoryStub{}
	audit := &workspaceUsageAuditStub{}
	service := newWorkspaceUsageService(authority, repository, audit)
	first, err := service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"workspace-a", "installation-1", "nightpos", "billing-service", "auth-7", "catalog-1"} {
		if strings.Contains(first.NextCursor, secret) || strings.Contains(string(decoded), secret) {
			t.Fatalf("opaque cursor exposed %q: token=%q decoded=%q", secret, first.NextCursor, decoded)
		}
	}
	baselineQueries, baselineAudits := len(repository.workspaceCalls), len(audit.requests)

	authority.grant.AuthorizationRevision = "auth-8"
	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: first.NextCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_scope_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("authorization revision mix err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}
	authority.grant = workspaceUsageGrant()
	authority.grant.SubjectID = "another-subject"
	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: first.NextCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_scope_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("subject scope mix err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}
	authority.grant = workspaceUsageGrant()
	authority.grant.ApplicationKey = "another-application"
	otherApplicationService := NewIdentityWorkspaceUsageApplicationService(IdentityWorkspaceUsageDependencies{
		ApplicationKey: "another-application", Authority: authority, Repository: repository, Audit: audit, CursorKey: workspaceUsageCursorKey,
	})
	_, err = otherApplicationService.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: first.NextCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_scope_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("application scope mix err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}

	authority.grant = workspaceUsageGrant()
	forgedGrant := workspaceUsageGrant()
	forgedGrant.InstallationID = "installation-outside"
	forgedCursor, err := encodeIdentityWorkspaceUsageCursor("workspace-a", "catalog-1", workspaceUsageCursorKey, forgedGrant, IdentityWorkspaceUsageContractVersionV2, IdentityWorkspaceUsageContractHashV2, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: forgedCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_scope_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("installation scope tamper err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}

	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 2, Cursor: first.NextCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_scope_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("page-size scope mix err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}

	drifted := identitymodel.IdentityWorkspaceUsageCatalogPage{CatalogRevision: "catalog-2", Workspaces: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-b")}}
	authority.page = &drifted
	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: first.NextCursor,
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_catalog_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("catalog revision drift err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}

	_, err = service.List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1, Cursor: first.NextCursor + "tampered",
	})
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_invalid" || len(repository.workspaceCalls) != baselineQueries || len(audit.requests) != baselineAudits {
		t.Fatalf("tampered cursor err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}
	// Every denied post-authorization attempt still crossed the authority's
	// synchronous allow/deny audit boundary; none emitted Identity's success audit.
	if len(authority.permissions) != 8 {
		t.Fatalf("authority audit decisions=%d want=8", len(authority.permissions))
	}
}

func TestWorkspaceIdentityUsageCursorRestartKeySemanticsFailClosed(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{
		grant: workspaceUsageGrant(),
		entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{
			activeWorkspaceUsageEntry("workspace-a"), activeWorkspaceUsageEntry("workspace-b"),
		},
	}
	repository := &workspaceUsageRepositoryStub{}
	audit := &workspaceUsageAuditStub{}
	request := IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	}
	first, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), request)
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}

	// Reconstructing the service with the same persisted host key preserves the
	// cursor while still re-authorizing and re-reading current facts.
	restarted := newWorkspaceUsageServiceWithKey(authority, repository, audit, append([]byte(nil), workspaceUsageCursorKey...))
	request.Cursor = first.NextCursor
	second, err := restarted.List(t.Context(), request)
	if err != nil || len(second.Items) != 1 || second.Items[0].WorkspaceID != "workspace-b" {
		t.Fatalf("same-key restart page=%+v err=%v", second, err)
	}
	queryCount, auditCount := len(repository.workspaceCalls), len(audit.requests)

	rotatedKey := []byte("fedcba9876543210fedcba9876543210")
	_, err = newWorkspaceUsageServiceWithKey(authority, repository, audit, rotatedKey).List(t.Context(), request)
	if apperror.CodeOf(err) != "backend.identity.workspace_usage_cursor_invalid" || len(repository.workspaceCalls) != queryCount || len(audit.requests) != auditCount {
		t.Fatalf("rotated-key restart err=%v queries=%d audits=%d", err, len(repository.workspaceCalls), len(audit.requests))
	}
}

func TestWorkspaceIdentityUsageRepositoryFailureHasAuthorityAttemptAuditButNoSuccessAudit(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-a")}}
	repositoryFailure := errors.New("aggregate query failed")
	repository := &workspaceUsageRepositoryStub{err: repositoryFailure}
	audit := &workspaceUsageAuditStub{}
	_, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	})
	if !errors.Is(err, repositoryFailure) || len(authority.permissions) != 1 || len(audit.requests) != 0 {
		t.Fatalf("err=%v authority=%d success_audits=%d", err, len(authority.permissions), len(audit.requests))
	}
}

func TestWorkspaceIdentityUsageActiveRoleRepositoryFailureHasNoSuccessAudit(t *testing.T) {
	authority := &workspaceUsageAuthorityStub{grant: workspaceUsageGrant(), entries: []identitymodel.IdentityWorkspaceUsageCatalogEntry{activeWorkspaceUsageEntry("workspace-a")}}
	repositoryFailure := errors.New("active role aggregate query failed")
	repository := &workspaceUsageRepositoryStub{
		groups:        []identitymodel.IdentityWorkspaceUsageGroup{{WorkspaceID: "workspace-a", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 1}},
		activeRoleErr: repositoryFailure,
	}
	audit := &workspaceUsageAuditStub{}
	_, err := newWorkspaceUsageService(authority, repository, audit).List(t.Context(), IdentityWorkspaceUsageRequest{
		ContractVersion: IdentityWorkspaceUsageContractVersionV2, ContractHash: IdentityWorkspaceUsageContractHashV2, AccessToken: "token", PageSize: 1,
	})
	if !errors.Is(err, repositoryFailure) || len(repository.workspaceCalls) != 1 || len(repository.activeRoleCalls) != 1 || len(audit.requests) != 0 {
		t.Fatalf("err=%v inventory_queries=%d active_role_queries=%d success_audits=%d", err, len(repository.workspaceCalls), len(repository.activeRoleCalls), len(audit.requests))
	}
}

func TestApplyWorkspaceIdentityUsageGroupsRejectsOutOfPageWorkspace(t *testing.T) {
	items := []identitymodel.IdentityWorkspaceUsage{{WorkspaceID: "workspace-a"}}
	err := applyIdentityWorkspaceUsageGroups(items, map[string]int{"workspace-a": 0}, []identitymodel.IdentityWorkspaceUsageGroup{{
		WorkspaceID: "workspace-outside", AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive, Count: 1,
	}})
	if err == nil {
		t.Fatal("out-of-page aggregate row accepted")
	}
}
