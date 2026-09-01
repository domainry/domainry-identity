package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type profileBindingRepositoryStub struct {
	binding      identitymodel.IdentityProfileBinding
	found        bool
	err          error
	lastMutation identitymodel.IdentityProfileBindingMutation
	events       []identitymodel.IdentityProfileBindingEvent
	receipt      identitymodel.IdentityProfileBindingReceipt
	receiptFound bool
	receiptErr   error
	executeErr   error
}

func (s *profileBindingRepositoryStub) GetIdentityProfileBinding(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.binding, s.found, s.err
}
func (s *profileBindingRepositoryStub) GetIdentityProfileBindingByKey(context.Context, string, string, string) (identitymodel.IdentityProfileBinding, bool, error) {
	return s.binding, s.found, s.err
}
func (s *profileBindingRepositoryStub) GetIdentityProfileBindingReceipt(context.Context, identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, bool, error) {
	if s.receiptErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, false, s.receiptErr
	}
	return s.receipt, s.receiptFound, s.err
}
func (s *profileBindingRepositoryStub) ExecuteIdentityProfileBindingMutation(_ context.Context, mutation identitymodel.IdentityProfileBindingMutation) (identitymodel.IdentityProfileBindingReceipt, error) {
	s.lastMutation = mutation
	if s.executeErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, s.executeErr
	}
	return identitymodel.IdentityProfileBindingReceipt{ID: "receipt", Binding: s.binding}, s.err
}
func (s *profileBindingRepositoryStub) ListIdentityProfileBindingEvents(context.Context, string, string, string) ([]identitymodel.IdentityProfileBindingEvent, error) {
	return s.events, s.err
}

type profileBindingRecordReaderStub struct {
	record map[string]any
	found  bool
	err    error
}

func (s profileBindingRecordReaderStub) GetIdentityProfileBindingRecord(context.Context, string, definitionmodel.ObjectSchema, string) (map[string]any, bool, error) {
	return s.record, s.found, s.err
}

type profileBindingIdentityStub struct {
	users map[string]identitymodel.IdentityUser
	err   error
}

func (s profileBindingIdentityStub) FindUser(_ context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	user, found := s.users[userID]
	return user, found, s.err
}

type profileBindingExternalClaimStub struct {
	verified bool
	err      error
}

type profileBindingApprovalStub struct {
	approved bool
	err      error
}

func (s profileBindingApprovalStub) VerifyIdentityProfileRebindApproval(context.Context, string, string, string, string, string, string) (bool, error) {
	return s.approved, s.err
}

type profileBindingSessionRevokerStub struct {
	users []string
	err   error
}

type profileBindingSystemRolesStub struct {
	roleIDs []string
	err     error
}

func (s profileBindingSystemRolesStub) ResolveIdentityProfileSystemRoleIDs(context.Context, string) ([]string, error) {
	return s.roleIDs, s.err
}

func (s *profileBindingSessionRevokerStub) RevokeIdentityProfileSessions(_ context.Context, _, userID, _ string) error {
	s.users = append(s.users, userID)
	return s.err
}

func (s profileBindingExternalClaimStub) IdentityUserHasExternalSubject(context.Context, string, string, string, string) (bool, error) {
	return s.verified, s.err
}

func TestProfileBindingClaimDerivesIdentityFromPrincipalAndVerifiesServerFacts(t *testing.T) {
	repository := &profileBindingRepositoryStub{}
	service := profileBindingTestService(repository, map[string]any{"identity_user": nil, "email": "Member@Example.com", "phone": "+1 (202) 555-0123", "external_subject": "oidc-1"}, true)
	principal := profileBindingPrincipal("member-user", "member.self")
	for _, test := range []struct {
		name, proofType, proofValue string
		external                    profileBindingExternalClaimStub
	}{
		{name: "email", proofType: "email", proofValue: "member@example.com"},
		{name: "phone", proofType: "phone", proofValue: "+1 2025550123"},
		{name: "external", proofType: "external_idp_subject", proofValue: "oidc-1", external: profileBindingExternalClaimStub{verified: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service.dependencies.ExternalClaims = test.external
			request := profileBindingCommand(identitymodel.IdentityProfileBindingClaim)
			request.IdentityUserID = "attacker-controlled"
			request.ClaimProofType, request.ClaimProofValue = test.proofType, test.proofValue
			if _, err := service.Execute(t.Context(), request, principal); err != nil {
				t.Fatal(err)
			}
			if repository.lastMutation.IdentityUserID != principal.UserID || repository.lastMutation.ClaimProofType != test.proofType || repository.lastMutation.RequestFingerprint == "" {
				t.Fatalf("mutation=%#v", repository.lastMutation)
			}
		})
	}
}

func TestProfileBindingActivationCommandsRejectInactiveOrBlacklistedProfile(t *testing.T) {
	for _, record := range []map[string]any{
		{"identity_user": nil, "status": "suspended", "blacklisted": false},
		{"identity_user": nil, "status": "active", "blacklisted": true},
	} {
		repository := &profileBindingRepositoryStub{}
		service := profileBindingTestService(repository, record, true)
		service.dependencies.Extensions = func() []identitymodel.IdentityProfileExtension {
			return []identitymodel.IdentityProfileExtension{{
				ObjectKey: "member_profile", IdentityRelationField: "identity_user",
				BusinessIdentity: identitymodel.BusinessIdentityBinding{
					Key: "member", StatusField: "status", ActiveStatusValues: []string{"active"}, BlacklistField: "blacklisted",
				},
				BindingLifecycle: identitymodel.IdentityProfileBindingLifecycle{
					AllowUnbound: true, ClaimProofs: []identitymodel.IdentityProfileClaimProof{{Type: "email", FieldKey: "email"}},
				},
			}}
		}
		request := profileBindingCommand(identitymodel.IdentityProfileBindingClaim)
		request.ClaimProofType, request.ClaimProofValue = "email", "member@example.com"
		if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("member-user", "member.self")); apperror.CodeOf(err) != "backend.identity.profile_inactive" {
			t.Fatalf("record=%#v error=%v", record, err)
		}
		if repository.lastMutation.Operation != "" {
			t.Fatalf("inactive profile reached repository mutation=%#v", repository.lastMutation)
		}
	}
}

func TestProfileBindingClaimRejectsUntrustedOrMismatchedProof(t *testing.T) {
	repository := &profileBindingRepositoryStub{}
	principal := profileBindingPrincipal("member-user", "member.self")
	for _, test := range []struct {
		name     string
		record   map[string]any
		users    map[string]identitymodel.IdentityUser
		proof    string
		value    string
		external profileBindingExternalClaimStub
		code     string
	}{
		{name: "unknown proof", record: map[string]any{"email": "member@example.com"}, proof: "unknown", value: "member@example.com", code: "backend.identity.profile_claim_proof_invalid"},
		{name: "profile mismatch", record: map[string]any{"email": "other@example.com"}, proof: "email", value: "member@example.com", code: "backend.identity.profile_claim_proof_invalid"},
		{name: "account mismatch", record: map[string]any{"email": "member@example.com"}, users: map[string]identitymodel.IdentityUser{"member-user": {ID: "member-user", Email: "other@example.com", Status: identitymodel.IdentityStatusActive}}, proof: "email", value: "member@example.com", code: "backend.identity.profile_claim_proof_invalid"},
		{name: "inactive account", record: map[string]any{"email": "member@example.com"}, users: map[string]identitymodel.IdentityUser{"member-user": {ID: "member-user", Email: "member@example.com", Status: identitymodel.IdentityStatusDisabled}}, proof: "email", value: "member@example.com", code: "backend.identity.profile_claim_identity_invalid"},
		{name: "external denied", record: map[string]any{"external_subject": "oidc-1"}, proof: "external_idp_subject", value: "oidc-1", external: profileBindingExternalClaimStub{}, code: "backend.identity.profile_claim_proof_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := profileBindingTestService(repository, test.record, true)
			if test.users != nil {
				service.dependencies.Identity = profileBindingIdentityStub{users: test.users}
			}
			service.dependencies.ExternalClaims = test.external
			request := profileBindingCommand(identitymodel.IdentityProfileBindingClaim)
			request.ClaimProofType, request.ClaimProofValue = test.proof, test.value
			if _, err := service.Execute(t.Context(), request, principal); apperror.CodeOf(err) != test.code {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProfileBindingManagedCommandPolicyAndTransitions(t *testing.T) {
	admin := profileBindingPrincipal("admin", "identity.profile_bindings.command")
	for _, test := range []struct {
		name      string
		operation identitymodel.IdentityProfileBindingOperation
		record    map[string]any
		edit      func(*IdentityProfileBindingCommandRequest)
		code      string
		wantUser  string
	}{
		{name: "invite", operation: identitymodel.IdentityProfileBindingInvite, record: map[string]any{}, edit: func(request *IdentityProfileBindingCommandRequest) { request.InvitationChannel = "email" }},
		{name: "bind", operation: identitymodel.IdentityProfileBindingBind, record: map[string]any{}, edit: func(request *IdentityProfileBindingCommandRequest) { request.IdentityUserID = "target" }, wantUser: "target"},
		{name: "rebind", operation: identitymodel.IdentityProfileBindingRebind, record: map[string]any{"identity_user": "old"}, edit: func(request *IdentityProfileBindingCommandRequest) {
			request.IdentityUserID, request.Reason = "target", "ownership corrected"
		}, wantUser: "target"},
		{name: "unlink", operation: identitymodel.IdentityProfileBindingUnlink, record: map[string]any{"identity_user": "old"}},
		{name: "invite bound", operation: identitymodel.IdentityProfileBindingInvite, record: map[string]any{"identity_user": "old"}, edit: func(request *IdentityProfileBindingCommandRequest) { request.InvitationChannel = "email" }, code: "backend.identity.profile_binding_invite_not_allowed"},
		{name: "bind bound", operation: identitymodel.IdentityProfileBindingBind, record: map[string]any{"identity_user": "old"}, edit: func(request *IdentityProfileBindingCommandRequest) { request.IdentityUserID = "target" }, code: "backend.identity.profile_already_bound"},
		{name: "rebind reason", operation: identitymodel.IdentityProfileBindingRebind, record: map[string]any{"identity_user": "old"}, edit: func(request *IdentityProfileBindingCommandRequest) { request.IdentityUserID = "target" }, code: "backend.identity.profile_rebind_reason_required"},
		{name: "rebind unchanged", operation: identitymodel.IdentityProfileBindingRebind, record: map[string]any{"identity_user": "target"}, edit: func(request *IdentityProfileBindingCommandRequest) {
			request.IdentityUserID, request.Reason = "target", "reason"
		}, code: "backend.identity.profile_binding_unchanged"},
		{name: "unlink empty", operation: identitymodel.IdentityProfileBindingUnlink, record: map[string]any{}, code: "backend.identity.profile_not_bound"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &profileBindingRepositoryStub{}
			service := profileBindingTestService(repository, test.record, true)
			request := profileBindingCommand(test.operation)
			if test.edit != nil {
				test.edit(&request)
			}
			_, err := service.Execute(t.Context(), request, admin)
			if (test.code == "" && err != nil) || (test.code != "" && apperror.CodeOf(err) != test.code) {
				t.Fatalf("error=%v want=%q", err, test.code)
			}
			if test.code == "" && repository.lastMutation.IdentityUserID != test.wantUser {
				t.Fatalf("mutation=%#v", repository.lastMutation)
			}
		})
	}
}

func TestProfileBindingApplicationBoundaryFailures(t *testing.T) {
	validRecord := map[string]any{"email": "member@example.com"}
	admin := profileBindingPrincipal("admin", "identity.profile_bindings.command")
	request := profileBindingCommand(identitymodel.IdentityProfileBindingInvite)
	request.InvitationChannel = "email"
	for _, test := range []struct {
		name      string
		service   *IdentityProfileBindingApplicationService
		request   IdentityProfileBindingCommandRequest
		principal identitymodel.Principal
		code      string
	}{
		{name: "unknown principal", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true), request: request, principal: identitymodel.Principal{}, code: "backend.workspace_scope_required"},
		{name: "invalid operation", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true), request: func() IdentityProfileBindingCommandRequest {
			value := request
			value.Operation = "invalid"
			return value
		}(), principal: admin, code: "backend.identity.profile_binding_operation_invalid"},
		{name: "permission", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true), request: request, principal: profileBindingPrincipal("user", "member.self"), code: "backend.identity.profile_binding_manage_required"},
		{name: "invalid command", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true), request: func() IdentityProfileBindingCommandRequest { value := request; value.IdempotencyKey = ""; return value }(), principal: admin, code: "backend.identity.profile_binding_command_invalid"},
		{name: "definition", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true), request: func() IdentityProfileBindingCommandRequest {
			value := request
			value.BindingKey = "missing"
			return value
		}(), principal: admin, code: "backend.identity.profile_binding_definition_not_found"},
		{name: "repository", service: profileBindingTestServiceWithoutRepository(validRecord), request: request, principal: admin, code: "backend.identity.profile_binding_unavailable"},
		{name: "record missing", service: profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, false), request: request, principal: admin, code: "backend.identity.profile_not_found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.service.Execute(t.Context(), test.request, test.principal); apperror.CodeOf(err) != test.code {
				t.Fatalf("error=%v want=%q", err, test.code)
			}
		})
	}
	failure := errors.New("record failed")
	service := profileBindingTestService(&profileBindingRepositoryStub{}, validRecord, true)
	service.dependencies.Records = profileBindingRecordReaderStub{err: failure}
	if _, err := service.Execute(t.Context(), request, admin); !errors.Is(err, failure) {
		t.Fatalf("record error=%v", err)
	}
	if _, found, err := NewIdentityProfileBindingApplicationService(IdentityProfileBindingDependencies{}).Get(t.Context(), "object", "profile", admin); found || apperror.CodeOf(err) != "backend.identity.profile_binding_unavailable" {
		t.Fatalf("get found=%v err=%v", found, err)
	}
}

func TestProfileBindingReadIsLimitedToManagerOrBoundIdentity(t *testing.T) {
	repository := &profileBindingRepositoryStub{
		binding: identitymodel.IdentityProfileBinding{WorkspaceID: "workspace", ObjectKey: "member_profile", ProfileID: "member-1", IdentityUserID: "member-user"},
		found:   true,
	}
	service := profileBindingTestService(repository, nil, true)
	for _, test := range []struct {
		name      string
		principal identitymodel.Principal
		code      string
	}{
		{name: "bound identity", principal: profileBindingPrincipal("member-user", "member.self")},
		{name: "manager", principal: profileBindingPrincipal("admin", "identity.profile_bindings.get")},
		{name: "another exact Permission is not an alias", principal: profileBindingPrincipal("admin", "identity.roles.list"), code: "backend.identity.profile_binding_read_denied"},
		{name: "different identity", principal: profileBindingPrincipal("other", "member.self"), code: "backend.identity.profile_binding_read_denied"},
		{name: "unknown", principal: identitymodel.Principal{}, code: "backend.workspace_scope_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, found, err := service.Get(t.Context(), "member_profile", "member-1", test.principal)
			if test.code == "" {
				if err != nil || !found {
					t.Fatalf("found=%v err=%v", found, err)
				}
				return
			}
			if found || apperror.CodeOf(err) != test.code {
				t.Fatalf("found=%v err=%v want=%s", found, err, test.code)
			}
		})
	}
	repository.found = false
	if _, found, err := service.Get(t.Context(), "member_profile", "missing", profileBindingPrincipal("admin", "identity.profile_bindings.get")); err != nil || found {
		t.Fatalf("missing found=%v err=%v", found, err)
	}
	repository.found, repository.err = true, errors.New("read failed")
	if _, _, err := service.Get(t.Context(), "member_profile", "member-1", profileBindingPrincipal("admin", "identity.profile_bindings.get")); !errors.Is(err, repository.err) {
		t.Fatalf("error=%v", err)
	}
}

func TestProfileBindingHighRiskRebindRequiresApprovalAndRevokesOldSessions(t *testing.T) {
	repository := &profileBindingRepositoryStub{}
	service := profileBindingTestService(repository, map[string]any{"identity_user": "old"}, true)
	extensions := service.dependencies.Extensions()
	extensions[0].BindingLifecycle.RebindRequiresApproval = true
	extensions[0].BindingLifecycle.RebindRevokesSessions = true
	service.dependencies.Extensions = func() []identitymodel.IdentityProfileExtension { return extensions }
	request := profileBindingCommand(identitymodel.IdentityProfileBindingRebind)
	request.IdentityUserID, request.Reason = "target", "verified account takeover recovery"
	if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("admin", "identity.profile_bindings.command")); apperror.CodeOf(err) != "backend.identity.profile_rebind_approval_required" {
		t.Fatalf("missing approval error=%v", err)
	}
	request.ApprovalID = "approval-1"
	service.dependencies.RebindApprovals = profileBindingApprovalStub{}
	if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("admin", "identity.profile_bindings.command")); apperror.CodeOf(err) != "backend.identity.profile_rebind_approval_required" {
		t.Fatalf("denied approval error=%v", err)
	}
	service.dependencies.RebindApprovals = profileBindingApprovalStub{approved: true}
	if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("admin", "identity.profile_bindings.command")); apperror.CodeOf(err) != "backend.identity.profile_rebind_session_revocation_unavailable" {
		t.Fatalf("revoker unavailable error=%v", err)
	}
	revoker := &profileBindingSessionRevokerStub{}
	service.dependencies.SessionRevoker = revoker
	if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("admin", "identity.profile_bindings.command")); err != nil {
		t.Fatal(err)
	}
	if len(revoker.users) != 1 || revoker.users[0] != "old" || repository.lastMutation.ApprovalID != "approval-1" {
		t.Fatalf("revoked=%v mutation=%#v", revoker.users, repository.lastMutation)
	}
	revoker.err = errors.New("revoke sessions")
	if _, err := service.Execute(t.Context(), request, profileBindingPrincipal("admin", "identity.profile_bindings.command")); !errors.Is(err, revoker.err) {
		t.Fatalf("revoker error=%v", err)
	}
}

func TestProfileBindingSupportNormalizesMembershipAndUniqueValues(t *testing.T) {
	if !identityProfileBindingStringAllowed([]string{" other ", " allowed "}, "allowed") {
		t.Fatal("trimmed allowed value was rejected")
	}
	if identityProfileBindingStringAllowed([]string{"", "other"}, "") ||
		identityProfileBindingStringAllowed([]string{"other"}, "missing") {
		t.Fatal("empty or missing target was accepted")
	}
	values := identityUniqueSortedStrings([]string{" beta ", "", "alpha", "beta"})
	if len(values) != 2 || values[0] != "alpha" || values[1] != "beta" {
		t.Fatalf("unique sorted values=%v", values)
	}
}

func TestProfileBindingExecuteCoversInputSystemRoleReceiptAndMutationFailures(t *testing.T) {
	admin := profileBindingPrincipal("admin", "identity.profile_bindings.command")
	validRecord := map[string]any{"identity_user": nil}
	repository := &profileBindingRepositoryStub{}
	service := profileBindingTestService(repository, validRecord, true)
	request := profileBindingCommand(identitymodel.IdentityProfileBindingInvite)
	request.InvitationChannel = "email"

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Execute(cancelled, request, admin); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	invalids := []func(*IdentityProfileBindingCommandRequest){
		func(r *IdentityProfileBindingCommandRequest) { r.ObjectKey = " " },
		func(r *IdentityProfileBindingCommandRequest) { r.ProfileID = " " },
		func(r *IdentityProfileBindingCommandRequest) { r.BindingKey = " " },
		func(r *IdentityProfileBindingCommandRequest) { r.IdempotencyKey = " " },
		func(r *IdentityProfileBindingCommandRequest) { r.ExpectedVersion = -1 },
	}
	for index, mutate := range invalids {
		candidate := request
		mutate(&candidate)
		if _, err := service.Execute(t.Context(), candidate, admin); apperror.CodeOf(err) != "backend.identity.profile_binding_command_invalid" {
			t.Fatalf("invalid %d=%v", index, err)
		}
	}

	service.dependencies.SystemRoles = profileBindingSystemRolesStub{roleIDs: []string{"role"}}
	if _, err := service.Execute(t.Context(), request, admin); err != nil || len(repository.lastMutation.SystemManagedRoleIDs) != 1 {
		t.Fatalf("system roles mutation=%#v err=%v", repository.lastMutation, err)
	}
	service.dependencies.SystemRoles = profileBindingSystemRolesStub{err: errors.New("roles")}
	if _, err := service.Execute(t.Context(), request, admin); !errors.Is(err, service.dependencies.SystemRoles.(profileBindingSystemRolesStub).err) {
		t.Fatalf("system roles error=%v", err)
	}
	service.dependencies.SystemRoles = nil

	repository.receiptErr = errors.New("receipt")
	if _, err := service.Execute(t.Context(), request, admin); !errors.Is(err, repository.receiptErr) {
		t.Fatalf("receipt error=%v", err)
	}
	repository.receiptErr = nil
	if _, err := service.Execute(t.Context(), request, admin); err != nil {
		t.Fatalf("capture normal fingerprint=%v", err)
	}
	repository.receiptFound = true
	repository.receipt = identitymodel.IdentityProfileBindingReceipt{RequestFingerprint: "different"}
	if _, err := service.Execute(t.Context(), request, admin); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("receipt conflict=%v", err)
	}
	repository.receipt.RequestFingerprint = repository.lastMutation.RequestFingerprint
	if receipt, err := service.Execute(t.Context(), request, admin); err != nil || !receipt.Replayed {
		t.Fatalf("receipt replay=%#v err=%v", receipt, err)
	}
	repository.receiptFound = false

	service.dependencies.Records = nil
	if _, err := service.Execute(t.Context(), request, admin); apperror.CodeOf(err) != "backend.identity.profile_binding_unavailable" {
		t.Fatalf("nil records=%v", err)
	}
	service = profileBindingTestService(repository, validRecord, true)
	repository.executeErr = errors.New("execute")
	if _, err := service.Execute(t.Context(), request, admin); !errors.Is(err, repository.executeErr) {
		t.Fatalf("execute error=%v", err)
	}
}

func TestProfileBindingCommandValidationCoversIndependentLifecycleConditions(t *testing.T) {
	principal := profileBindingPrincipal("member-user", "member.self")
	repository := &profileBindingRepositoryStub{}
	service := profileBindingTestService(repository, map[string]any{"identity_user": nil, "email": "member@example.com"}, true)
	extension, _, _ := service.profileBindingDefinition("member_profile", "member")

	invite := profileBindingCommand(identitymodel.IdentityProfileBindingInvite)
	invite.InvitationChannel = "email"
	noUnbound := extension
	noUnbound.BindingLifecycle.AllowUnbound = false
	if _, err := service.validateProfileBindingCommand(t.Context(), invite, identitymodel.IdentityProfileBindingInvite, noUnbound, map[string]any{}, principal); apperror.CodeOf(err) != "backend.identity.profile_binding_invite_not_allowed" {
		t.Fatalf("invite unbound=%v", err)
	}
	invite.InvitationChannel = "fax"
	if _, err := service.validateProfileBindingCommand(t.Context(), invite, identitymodel.IdentityProfileBindingInvite, extension, map[string]any{}, principal); apperror.CodeOf(err) != "backend.identity.profile_binding_invite_not_allowed" {
		t.Fatalf("invite channel=%v", err)
	}
	claim := profileBindingCommand(identitymodel.IdentityProfileBindingClaim)
	claim.ClaimProofType, claim.ClaimProofValue = "email", "member@example.com"
	if _, err := service.validateProfileBindingCommand(t.Context(), claim, identitymodel.IdentityProfileBindingClaim, extension, map[string]any{"identity_user": "existing"}, principal); apperror.CodeOf(err) != "backend.identity.profile_already_bound" {
		t.Fatalf("claim bound=%v", err)
	}
	if _, err := service.validateProfileBindingCommand(t.Context(), claim, identitymodel.IdentityProfileBindingClaim, noUnbound, map[string]any{}, principal); apperror.CodeOf(err) != "backend.identity.profile_already_bound" {
		t.Fatalf("claim unbound=%v", err)
	}
	rebind := profileBindingCommand(identitymodel.IdentityProfileBindingRebind)
	rebind.IdentityUserID, rebind.Reason = "target", "reason"
	if _, err := service.validateProfileBindingCommand(t.Context(), rebind, identitymodel.IdentityProfileBindingRebind, extension, map[string]any{}, principal); apperror.CodeOf(err) != "backend.identity.profile_rebind_reason_required" {
		t.Fatalf("rebind empty current=%v", err)
	}
	rebind.IdentityUserID = "missing"
	if _, err := service.validateProfileBindingCommand(t.Context(), rebind, identitymodel.IdentityProfileBindingRebind, extension, map[string]any{"identity_user": "old"}, principal); apperror.CodeOf(err) != "backend.identity.profile_binding_target_invalid" {
		t.Fatalf("rebind target=%v", err)
	}
	rebind.IdentityUserID = "target"
	approvalExtension := extension
	approvalExtension.BindingLifecycle.RebindRequiresApproval = true
	rebind.ApprovalID = "approval"
	service.dependencies.RebindApprovals = nil
	if _, err := service.validateProfileBindingCommand(t.Context(), rebind, identitymodel.IdentityProfileBindingRebind, approvalExtension, map[string]any{"identity_user": "old"}, principal); apperror.CodeOf(err) != "backend.identity.profile_rebind_approval_required" {
		t.Fatalf("nil approval verifier=%v", err)
	}
	service.dependencies.RebindApprovals = profileBindingApprovalStub{err: errors.New("approval")}
	if _, err := service.validateProfileBindingCommand(t.Context(), rebind, identitymodel.IdentityProfileBindingRebind, approvalExtension, map[string]any{"identity_user": "old"}, principal); !errors.Is(err, service.dependencies.RebindApprovals.(profileBindingApprovalStub).err) {
		t.Fatalf("approval error=%v", err)
	}
	if _, err := service.validateProfileBindingCommand(t.Context(), invite, "unknown", extension, map[string]any{}, principal); apperror.CodeOf(err) != "backend.identity.profile_binding_operation_invalid" {
		t.Fatalf("unknown operation=%v", err)
	}
}

func TestProfileBindingBusinessActiveAndIdentityValidationEdges(t *testing.T) {
	if !identityProfileBindingBusinessActive(identitymodel.BusinessIdentityBinding{}, map[string]any{}) {
		t.Fatal("unconfigured business identity was inactive")
	}
	statusBinding := identitymodel.BusinessIdentityBinding{StatusField: "status", ActiveStatusValues: []string{"active"}}
	if identityProfileBindingBusinessActive(statusBinding, map[string]any{"status": "inactive"}) ||
		!identityProfileBindingBusinessActive(statusBinding, map[string]any{"status": "active"}) {
		t.Fatal("status policy mismatch")
	}
	blockBinding := identitymodel.BusinessIdentityBinding{BlacklistField: "blocked"}
	for _, value := range []any{true, "true", "1"} {
		if identityProfileBindingBusinessActive(blockBinding, map[string]any{"blocked": value}) {
			t.Fatalf("blacklist value %v was active", value)
		}
	}
	for _, value := range []any{false, "false"} {
		if !identityProfileBindingBusinessActive(blockBinding, map[string]any{"blocked": value}) {
			t.Fatalf("blacklist value %v was inactive", value)
		}
	}

	service := profileBindingTestService(&profileBindingRepositoryStub{}, map[string]any{}, true)
	if _, err := service.validateTargetIdentity(t.Context(), ""); apperror.CodeOf(err) != "backend.identity.profile_binding_target_invalid" {
		t.Fatalf("blank target=%v", err)
	}
	identity := service.dependencies.Identity
	service.dependencies.Identity = nil
	if _, err := service.validateTargetIdentity(t.Context(), "target"); apperror.CodeOf(err) != "backend.identity.profile_binding_target_invalid" {
		t.Fatalf("nil identity=%v", err)
	}
	service.dependencies.Identity = profileBindingIdentityStub{err: errors.New("identity")}
	if _, err := service.validateTargetIdentity(t.Context(), "target"); !errors.Is(err, service.dependencies.Identity.(profileBindingIdentityStub).err) {
		t.Fatalf("identity error=%v", err)
	}
	service.dependencies.Identity = profileBindingIdentityStub{users: map[string]identitymodel.IdentityUser{}}
	if _, err := service.validateTargetIdentity(t.Context(), "target"); apperror.CodeOf(err) != "backend.identity.profile_binding_target_invalid" {
		t.Fatalf("missing target=%v", err)
	}
	service.dependencies.Identity = profileBindingIdentityStub{users: map[string]identitymodel.IdentityUser{"target": {ID: "target", Status: identitymodel.IdentityStatusDisabled}}}
	if _, err := service.validateTargetIdentity(t.Context(), "target"); apperror.CodeOf(err) != "backend.identity.profile_binding_target_invalid" {
		t.Fatalf("inactive target=%v", err)
	}
	service.dependencies.Identity = identity
}

func TestProfileBindingClaimVerificationAndDefinitionDependencyEdges(t *testing.T) {
	service := profileBindingTestService(&profileBindingRepositoryStub{}, map[string]any{}, true)
	extension, _, _ := service.profileBindingDefinition("member_profile", "member")
	record := map[string]any{"email": "member@example.com", "phone": "+12025550123", "external_subject": "subject"}
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "email", ""); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("blank proof=%v", err)
	}
	identity := service.dependencies.Identity
	service.dependencies.Identity = nil
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "email", "member@example.com"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("nil identity=%v", err)
	}
	service.dependencies.Identity = identity
	if err := service.verifyProfileClaim(t.Context(), extension, map[string]any{}, "workspace", "member-user", "email", "member@example.com"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("blank profile value=%v", err)
	}
	service.dependencies.Identity = profileBindingIdentityStub{err: errors.New("identity")}
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "email", "member@example.com"); !errors.Is(err, service.dependencies.Identity.(profileBindingIdentityStub).err) {
		t.Fatalf("claim identity error=%v", err)
	}
	for name, user := range map[string]identitymodel.IdentityUser{
		"missing":  {},
		"inactive": {ID: "member-user", Status: identitymodel.IdentityStatusDisabled},
	} {
		users := map[string]identitymodel.IdentityUser{}
		if user.ID != "" {
			users["member-user"] = user
		}
		service.dependencies.Identity = profileBindingIdentityStub{users: users}
		if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "email", "member@example.com"); apperror.CodeOf(err) != "backend.identity.profile_claim_identity_invalid" {
			t.Fatalf("%s user=%v", name, err)
		}
	}
	service.dependencies.Identity = profileBindingIdentityStub{users: map[string]identitymodel.IdentityUser{
		"member-user": {ID: "member-user", Email: "other@example.com", Phone: "+10000000000", Status: identitymodel.IdentityStatusActive},
	}}
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "email", "member@example.com"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("email mismatch=%v", err)
	}
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "phone", "+12025550123"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("phone mismatch=%v", err)
	}
	service.dependencies.Identity = identity
	service.dependencies.ExternalClaims = nil
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "external_idp_subject", "subject"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("nil external claims=%v", err)
	}
	service.dependencies.ExternalClaims = profileBindingExternalClaimStub{err: errors.New("external")}
	if err := service.verifyProfileClaim(t.Context(), extension, record, "workspace", "member-user", "external_idp_subject", "subject"); !errors.Is(err, service.dependencies.ExternalClaims.(profileBindingExternalClaimStub).err) {
		t.Fatalf("external error=%v", err)
	}
	customExtension := extension
	customExtension.BindingLifecycle.ClaimProofs = append(customExtension.BindingLifecycle.ClaimProofs, identitymodel.IdentityProfileClaimProof{Type: "custom", FieldKey: "custom"})
	record["custom"] = "value"
	if err := service.verifyProfileClaim(t.Context(), customExtension, record, "workspace", "member-user", "custom", "value"); apperror.CodeOf(err) != "backend.identity.profile_claim_proof_invalid" {
		t.Fatalf("unsupported proof type=%v", err)
	}

	service.dependencies.Objects = nil
	if _, _, found := service.profileBindingDefinition("member_profile", "member"); found {
		t.Fatal("definition found without objects")
	}
	service.dependencies.Objects = func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{{Key: "member_profile"}} }
	service.dependencies.Extensions = nil
	if _, _, found := service.profileBindingDefinition("member_profile", "member"); found {
		t.Fatal("definition found without extensions")
	}
	service.dependencies.Extensions = func() []identitymodel.IdentityProfileExtension {
		return []identitymodel.IdentityProfileExtension{{ObjectKey: "other", BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "member"}}}
	}
	if _, _, found := service.profileBindingDefinition("member_profile", "member"); found {
		t.Fatal("mismatched extension was selected")
	}
}

func profileBindingTestService(repository *profileBindingRepositoryStub, record map[string]any, found bool) *IdentityProfileBindingApplicationService {
	object := definitionmodel.ObjectSchema{Key: "member_profile"}
	extension := identitymodel.IdentityProfileExtension{
		ObjectKey: "member_profile", IdentityRelationField: "identity_user",
		BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "member"},
		BindingLifecycle: identitymodel.IdentityProfileBindingLifecycle{
			AllowUnbound: true, InvitationChannels: []string{"email", "sms"},
			ClaimProofs: []identitymodel.IdentityProfileClaimProof{{Type: "email", FieldKey: "email"}, {Type: "phone", FieldKey: "phone"}, {Type: "external_idp_subject", FieldKey: "external_subject"}},
		},
	}
	return NewIdentityProfileBindingApplicationService(IdentityProfileBindingDependencies{
		Repository: repository, Records: profileBindingRecordReaderStub{record: record, found: found},
		Identity: profileBindingIdentityStub{users: map[string]identitymodel.IdentityUser{
			"member-user": {ID: "member-user", Email: "member@example.com", Phone: "+12025550123", Status: identitymodel.IdentityStatusActive},
			"target":      {ID: "target", Status: identitymodel.IdentityStatusActive},
		}},
		Objects: func() []definitionmodel.ObjectSchema { return []definitionmodel.ObjectSchema{object} },
		Extensions: func() []identitymodel.IdentityProfileExtension {
			return []identitymodel.IdentityProfileExtension{extension}
		},
	})
}

func profileBindingTestServiceWithoutRepository(record map[string]any) *IdentityProfileBindingApplicationService {
	service := profileBindingTestService(&profileBindingRepositoryStub{}, record, true)
	service.dependencies.Repository = nil
	return service
}

func profileBindingPrincipal(userID, permission string) identitymodel.Principal {
	return identitymodel.Principal{Known: true, UserID: userID, WorkspaceID: "workspace", Role: identitymodel.RoleSchema{Permissions: []string{permission}}}
}

func profileBindingCommand(operation identitymodel.IdentityProfileBindingOperation) IdentityProfileBindingCommandRequest {
	return IdentityProfileBindingCommandRequest{
		ObjectKey: "member_profile", ProfileID: "member-1", BindingKey: "member", Operation: string(operation),
		ExpectedVersion: 0, IdempotencyKey: "command-1",
	}
}
