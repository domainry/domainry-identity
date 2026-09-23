package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type embeddedHandlerProfileRecordContextKey struct{}

type embeddedHandlerProfileRecord struct {
	objectKey string
	profileID string
	record    map[string]any
}

// WithEmbeddedHandlerProfileRecord is called only by Identity's transaction-
// bound module adapter after Runtime has validated a staged profile create.
// The deployment-neutral/unbound HandlerDelivery path cannot activate it.
func WithEmbeddedHandlerProfileRecord(ctx context.Context, objectKey, profileID string, record map[string]any) context.Context {
	if ctx == nil || strings.TrimSpace(objectKey) == "" || strings.TrimSpace(profileID) == "" || len(record) == 0 {
		return ctx
	}
	cloned := make(map[string]any, len(record))
	for key, value := range record {
		cloned[key] = value
	}
	return context.WithValue(ctx, embeddedHandlerProfileRecordContextKey{}, embeddedHandlerProfileRecord{objectKey: strings.TrimSpace(objectKey), profileID: strings.TrimSpace(profileID), record: cloned})
}

func embeddedHandlerProfileRecordFromContext(ctx context.Context, objectKey, profileID string) (map[string]any, bool) {
	if ctx == nil {
		return nil, false
	}
	value, ok := ctx.Value(embeddedHandlerProfileRecordContextKey{}).(embeddedHandlerProfileRecord)
	if !ok || value.objectKey != strings.TrimSpace(objectKey) || value.profileID != strings.TrimSpace(profileID) || len(value.record) == 0 {
		return nil, false
	}
	cloned := make(map[string]any, len(value.record))
	for key, item := range value.record {
		cloned[key] = item
	}
	return cloned, true
}

type IdentityProfileBindingRecordReader interface {
	GetIdentityProfileBindingRecord(context.Context, string, definitionmodel.ObjectSchema, string) (map[string]any, bool, error)
}

type IdentityProfileExternalClaimVerifier interface {
	IdentityUserHasExternalSubject(context.Context, string, string, string, string) (bool, error)
}

type IdentityProfileRebindApprovalVerifier interface {
	VerifyIdentityProfileRebindApproval(context.Context, string, string, string, string, string, string) (bool, error)
}

type IdentityProfileSessionRevoker interface {
	RevokeIdentityProfileSessions(context.Context, string, string, string) error
}

type IdentityProfileSystemRoleResolver interface {
	ResolveIdentityProfileSystemRoleIDs(context.Context, string) ([]string, error)
}

type IdentityProfileBindingDependencies struct {
	Repository identityrepository.IdentityProfileBindingRepository
	Records    IdentityProfileBindingRecordReader
	Identity   interface {
		FindUser(context.Context, string) (identitymodel.IdentityUser, bool, error)
	}
	ExternalClaims  IdentityProfileExternalClaimVerifier
	RebindApprovals IdentityProfileRebindApprovalVerifier
	SessionRevoker  IdentityProfileSessionRevoker
	SystemRoles     IdentityProfileSystemRoleResolver
	Objects         func() []definitionmodel.ObjectSchema
	Extensions      func() []identitymodel.IdentityProfileExtension
}

type IdentityProfileBindingCommandRequest struct {
	ObjectKey         string `json:"object_key"`
	ProfileID         string `json:"profile_id"`
	BindingKey        string `json:"binding_key"`
	Operation         string `json:"operation"`
	IdentityUserID    string `json:"identity_user_id,omitempty"`
	InvitationChannel string `json:"invitation_channel,omitempty"`
	ClaimProofType    string `json:"claim_proof_type,omitempty"`
	ClaimProofValue   string `json:"claim_proof_value,omitempty"`
	Reason            string `json:"reason,omitempty"`
	ApprovalID        string `json:"approval_id,omitempty"`
	ExpectedVersion   int64  `json:"expected_version"`
	IdempotencyKey    string `json:"idempotency_key"`
}

type IdentityProfileBindingApplicationService struct {
	dependencies IdentityProfileBindingDependencies
}

func NewIdentityProfileBindingApplicationService(dependencies IdentityProfileBindingDependencies) *IdentityProfileBindingApplicationService {
	return &IdentityProfileBindingApplicationService{dependencies: dependencies}
}

func (s *IdentityProfileBindingApplicationService) Execute(ctx context.Context, request IdentityProfileBindingCommandRequest, principal identitymodel.Principal) (identitymodel.IdentityProfileBindingReceipt, error) {
	if err := ctx.Err(); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if _, err := identitymodel.CommandScopeForPrincipal(principal); err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	operation := identitymodel.IdentityProfileBindingOperation(strings.TrimSpace(request.Operation))
	if !identityProfileBindingOperationAllowed(operation) {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_operation_invalid")
	}
	if operation != identitymodel.IdentityProfileBindingClaim &&
		!identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityActionProfileBindingsCommand) {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindForbidden, "backend.identity.profile_binding_manage_required")
	}
	if probe, ok, probeErr := s.replayProbe(ctx, request, principal); probeErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, probeErr
	} else if ok {
		if receipt, found, receiptErr := s.dependencies.Repository.GetIdentityProfileBindingReceipt(ctx, probe); receiptErr != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, receiptErr
		} else if found {
			if receipt.RequestFingerprint != probe.RequestFingerprint {
				return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindConflict, "backend.idempotency_key_reused")
			}
			receipt.Replayed = true
			return receipt, nil
		}
	}
	mutation, currentUserID, err := s.PrepareMutation(ctx, request, principal)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if receipt, found, receiptErr := s.dependencies.Repository.GetIdentityProfileBindingReceipt(ctx, mutation); receiptErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, receiptErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Replayed = true
		return receipt, nil
	}
	receipt, err := s.dependencies.Repository.ExecuteIdentityProfileBindingMutation(ctx, mutation)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if mutation.Operation == identitymodel.IdentityProfileBindingRebind {
		extension, _, _ := s.profileBindingDefinition(mutation.ObjectKey, mutation.BindingKey)
		if extension.BindingLifecycle.RebindRevokesSessions {
			if s.dependencies.SessionRevoker == nil {
				return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindInternal, "backend.identity.profile_rebind_session_revocation_unavailable")
			}
			if err := s.dependencies.SessionRevoker.RevokeIdentityProfileSessions(ctx, principal.WorkspaceID, currentUserID, "identity_profile_rebind"); err != nil {
				return identitymodel.IdentityProfileBindingReceipt{}, err
			}
		}
	}
	return receipt, nil
}

func (s *IdentityProfileBindingApplicationService) replayProbe(ctx context.Context, request IdentityProfileBindingCommandRequest, principal identitymodel.Principal) (identitymodel.IdentityProfileBindingMutation, bool, error) {
	operation := identitymodel.IdentityProfileBindingOperation(strings.TrimSpace(request.Operation))
	objectKey, profileID := strings.TrimSpace(request.ObjectKey), strings.TrimSpace(request.ProfileID)
	bindingKey, idempotencyKey := strings.TrimSpace(request.BindingKey), strings.TrimSpace(request.IdempotencyKey)
	if s.dependencies.Repository == nil || !identityProfileBindingOperationAllowed(operation) || objectKey == "" || profileID == "" || bindingKey == "" || idempotencyKey == "" || request.ExpectedVersion < 0 {
		return identitymodel.IdentityProfileBindingMutation{}, false, nil
	}
	extension, _, found := s.profileBindingDefinition(objectKey, bindingKey)
	if !found {
		return identitymodel.IdentityProfileBindingMutation{}, false, nil
	}
	mutation := identitymodel.IdentityProfileBindingMutation{
		WorkspaceID: principal.WorkspaceID, BindingKey: bindingKey, ObjectKey: objectKey, ProfileID: profileID,
		IdentityField: extension.IdentityRelationField, Operation: operation,
		IdentityUserID: profileBindingRequestedTarget(request, operation, principal.UserID), InvitationChannel: strings.TrimSpace(request.InvitationChannel),
		ClaimProofType: strings.TrimSpace(request.ClaimProofType), Reason: strings.TrimSpace(request.Reason), ApprovalID: strings.TrimSpace(request.ApprovalID),
		ExpectedVersion: request.ExpectedVersion, IdempotencyKey: idempotencyKey, ActorID: principal.UserID, CausationID: principal.CausationID,
	}
	if s.dependencies.SystemRoles != nil {
		roleIDs, err := s.dependencies.SystemRoles.ResolveIdentityProfileSystemRoleIDs(ctx, bindingKey)
		if err != nil {
			return identitymodel.IdentityProfileBindingMutation{}, false, err
		}
		mutation.SystemManagedRoleIDs = roleIDs
	}
	mutation.RequestFingerprint = identityProfileBindingFingerprint(mutation)
	return mutation, true, nil
}

// PrepareMutation performs the complete metadata, business-record, claim,
// target, approval, and role-policy validation without writing. Composite
// Identity delivery uses the returned mutation inside its own transaction.
func (s *IdentityProfileBindingApplicationService) PrepareMutation(ctx context.Context, request IdentityProfileBindingCommandRequest, principal identitymodel.Principal) (identitymodel.IdentityProfileBindingMutation, string, error) {
	return s.prepareMutation(ctx, request, principal, nil, identitycontract.IdentityActionProfileBindingsCommand)
}

// PrepareMutationForAtomicDelivery accepts one already-validated prospective
// target user. This is the only path that may bind a profile in the same
// transaction that creates that user; public profile commands still require a
// persisted target.
func (s *IdentityProfileBindingApplicationService) PrepareMutationForAtomicDelivery(ctx context.Context, request IdentityProfileBindingCommandRequest, principal identitymodel.Principal, target identitymodel.IdentityUser, permissionKey string) (identitymodel.IdentityProfileBindingMutation, string, error) {
	return s.prepareMutation(ctx, request, principal, &target, permissionKey)
}

func (s *IdentityProfileBindingApplicationService) prepareMutation(ctx context.Context, request IdentityProfileBindingCommandRequest, principal identitymodel.Principal, prospectiveTarget *identitymodel.IdentityUser, permissionKey string) (identitymodel.IdentityProfileBindingMutation, string, error) {
	if err := ctx.Err(); err != nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", err
	}
	if _, err := identitymodel.CommandScopeForPrincipal(principal); err != nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	operation := identitymodel.IdentityProfileBindingOperation(strings.TrimSpace(request.Operation))
	if !identityProfileBindingOperationAllowed(operation) {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_operation_invalid")
	}
	if operation != identitymodel.IdentityProfileBindingClaim &&
		!identitycontract.IdentityRoleHasPermissionKey(principal.Role, strings.TrimSpace(permissionKey)) {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindForbidden, "backend.identity.profile_binding_manage_required")
	}
	request.ObjectKey = strings.TrimSpace(request.ObjectKey)
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	request.BindingKey = strings.TrimSpace(request.BindingKey)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.ObjectKey == "" || request.ProfileID == "" || request.BindingKey == "" || request.IdempotencyKey == "" || request.ExpectedVersion < 0 {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_command_invalid")
	}
	extension, object, found := s.profileBindingDefinition(request.ObjectKey, request.BindingKey)
	if !found {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindNotFound, "backend.identity.profile_binding_definition_not_found")
	}
	if s.dependencies.Repository == nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	mutation := identitymodel.IdentityProfileBindingMutation{
		WorkspaceID: principal.WorkspaceID, BindingKey: request.BindingKey, ObjectKey: request.ObjectKey, ProfileID: request.ProfileID,
		IdentityField: extension.IdentityRelationField, Operation: operation, IdentityUserID: profileBindingRequestedTarget(request, operation, principal.UserID),
		InvitationChannel: strings.TrimSpace(request.InvitationChannel), ClaimProofType: strings.TrimSpace(request.ClaimProofType),
		Reason: strings.TrimSpace(request.Reason), ExpectedVersion: request.ExpectedVersion, IdempotencyKey: request.IdempotencyKey, ActorID: principal.UserID, CausationID: principal.CausationID,
		ApprovalID: strings.TrimSpace(request.ApprovalID),
	}
	if s.dependencies.SystemRoles != nil {
		resolvedRoleIDs, roleErr := s.dependencies.SystemRoles.ResolveIdentityProfileSystemRoleIDs(ctx, request.BindingKey)
		if roleErr != nil {
			return identitymodel.IdentityProfileBindingMutation{}, "", roleErr
		}
		mutation.SystemManagedRoleIDs = resolvedRoleIDs
	}
	if s.dependencies.Records == nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	record, recordFound, err := s.dependencies.Records.GetIdentityProfileBindingRecord(ctx, principal.WorkspaceID, object, request.ProfileID)
	if err != nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", err
	}
	profileRecordStaged := false
	if !recordFound {
		if embedded, ok := embeddedHandlerProfileRecordFromContext(ctx, request.ObjectKey, request.ProfileID); ok {
			record, recordFound = embedded, true
			profileRecordStaged = true
		}
	}
	if !recordFound {
		return identitymodel.IdentityProfileBindingMutation{}, "", profileBindingError(apperror.KindNotFound, "backend.identity.profile_not_found")
	}
	currentUserID := identityProfileBindingRecordString(record[extension.IdentityRelationField])
	targetUserID, err := s.validateProfileBindingCommandForTarget(ctx, request, operation, extension, record, principal, prospectiveTarget)
	if err != nil {
		return identitymodel.IdentityProfileBindingMutation{}, "", err
	}
	mutation.IdentityUserID = targetUserID
	mutation.ProfileRecordStaged = profileRecordStaged
	mutation.RequestFingerprint = identityProfileBindingFingerprint(mutation)
	return mutation, currentUserID, nil
}

func profileBindingRequestedTarget(request IdentityProfileBindingCommandRequest, operation identitymodel.IdentityProfileBindingOperation, principalUserID string) string {
	switch operation {
	case identitymodel.IdentityProfileBindingClaim:
		return strings.TrimSpace(principalUserID)
	case identitymodel.IdentityProfileBindingBind, identitymodel.IdentityProfileBindingRebind:
		return strings.TrimSpace(request.IdentityUserID)
	default:
		return ""
	}
}

func (s *IdentityProfileBindingApplicationService) Get(ctx context.Context, objectKey, profileID string, principal identitymodel.Principal) (identitymodel.IdentityProfileBinding, bool, error) {
	if _, err := identitymodel.QueryScopeForPrincipal(principal); err != nil {
		return identitymodel.IdentityProfileBinding{}, false, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	if s.dependencies.Repository == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	binding, found, err := s.dependencies.Repository.GetIdentityProfileBinding(ctx, principal.WorkspaceID, strings.TrimSpace(objectKey), strings.TrimSpace(profileID))
	if err != nil || !found {
		return binding, found, err
	}
	canManage := identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityActionProfileBindingsGet)
	if !canManage && strings.TrimSpace(binding.IdentityUserID) != strings.TrimSpace(principal.UserID) {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingError(apperror.KindForbidden, "backend.identity.profile_binding_read_denied")
	}
	return binding, true, nil
}

// CurrentBinding is an internal command-orchestration read. Its caller must
// already have authorized either the profile-binding command or the composed
// HandlerDelivery operation; it deliberately avoids requiring the separate
// UI/read permission during one atomic command.
func (s *IdentityProfileBindingApplicationService) CurrentBinding(ctx context.Context, workspaceID, objectKey, profileID string) (identitymodel.IdentityProfileBinding, bool, error) {
	if s == nil || s.dependencies.Repository == nil {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	return s.dependencies.Repository.GetIdentityProfileBinding(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(objectKey), strings.TrimSpace(profileID))
}

func (s *IdentityProfileBindingApplicationService) validateProfileBindingCommand(ctx context.Context, request IdentityProfileBindingCommandRequest, operation identitymodel.IdentityProfileBindingOperation, extension identitymodel.IdentityProfileExtension, record map[string]any, principal identitymodel.Principal) (string, error) {
	return s.validateProfileBindingCommandForTarget(ctx, request, operation, extension, record, principal, nil)
}

func (s *IdentityProfileBindingApplicationService) validateProfileBindingCommandForTarget(ctx context.Context, request IdentityProfileBindingCommandRequest, operation identitymodel.IdentityProfileBindingOperation, extension identitymodel.IdentityProfileExtension, record map[string]any, principal identitymodel.Principal, prospectiveTarget *identitymodel.IdentityUser) (string, error) {
	currentUserID := identityProfileBindingRecordString(record[extension.IdentityRelationField])
	if operation != identitymodel.IdentityProfileBindingUnlink && !identityProfileBindingBusinessActive(extension.BusinessIdentity, record) {
		return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_inactive")
	}
	switch operation {
	case identitymodel.IdentityProfileBindingInvite:
		channel := strings.TrimSpace(request.InvitationChannel)
		if currentUserID != "" || !extension.BindingLifecycle.AllowUnbound || !identityProfileBindingStringAllowed(extension.BindingLifecycle.InvitationChannels, channel) {
			return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_binding_invite_not_allowed")
		}
		return "", nil
	case identitymodel.IdentityProfileBindingClaim:
		if currentUserID != "" || !extension.BindingLifecycle.AllowUnbound {
			return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_already_bound")
		}
		if err := s.verifyProfileClaim(ctx, extension, record, principal.WorkspaceID, principal.UserID, strings.TrimSpace(request.ClaimProofType), strings.TrimSpace(request.ClaimProofValue)); err != nil {
			return "", err
		}
		return principal.UserID, nil
	case identitymodel.IdentityProfileBindingBind:
		if currentUserID != "" {
			return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_already_bound")
		}
		return s.validateTargetIdentityForDelivery(ctx, strings.TrimSpace(request.IdentityUserID), prospectiveTarget)
	case identitymodel.IdentityProfileBindingRebind:
		if currentUserID == "" || strings.TrimSpace(request.Reason) == "" {
			return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_rebind_reason_required")
		}
		targetUserID, err := s.validateTargetIdentityForDelivery(ctx, strings.TrimSpace(request.IdentityUserID), prospectiveTarget)
		if err != nil {
			return "", err
		}
		if targetUserID == currentUserID {
			return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_binding_unchanged")
		}
		if extension.BindingLifecycle.RebindRequiresApproval {
			approvalID := strings.TrimSpace(request.ApprovalID)
			if approvalID == "" || s.dependencies.RebindApprovals == nil {
				return "", profileBindingError(apperror.KindForbidden, "backend.identity.profile_rebind_approval_required")
			}
			approved, approvalErr := s.dependencies.RebindApprovals.VerifyIdentityProfileRebindApproval(ctx, principal.WorkspaceID, approvalID, request.ObjectKey, request.ProfileID, currentUserID, targetUserID)
			if approvalErr != nil {
				return "", approvalErr
			}
			if !approved {
				return "", profileBindingError(apperror.KindForbidden, "backend.identity.profile_rebind_approval_required")
			}
		}
		return targetUserID, nil
	case identitymodel.IdentityProfileBindingUnlink:
		if currentUserID == "" {
			return "", profileBindingError(apperror.KindConflict, "backend.identity.profile_not_bound")
		}
		return "", nil
	default:
		return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_operation_invalid")
	}
}

func identityProfileBindingBusinessActive(binding identitymodel.BusinessIdentityBinding, record map[string]any) bool {
	if field := strings.TrimSpace(binding.StatusField); field != "" {
		status := identityProfileBindingRecordString(record[field])
		active := false
		for _, allowed := range binding.ActiveStatusValues {
			if status == strings.TrimSpace(allowed) {
				active = true
				break
			}
		}
		if !active {
			return false
		}
	}
	if field := strings.TrimSpace(binding.BlacklistField); field != "" {
		switch value := record[field].(type) {
		case bool:
			if value {
				return false
			}
		default:
			normalized := strings.ToLower(identityProfileBindingRecordString(value))
			if normalized == "true" || normalized == "1" {
				return false
			}
		}
	}
	return true
}

func (s *IdentityProfileBindingApplicationService) validateTargetIdentity(ctx context.Context, userID string) (string, error) {
	return s.validateTargetIdentityForDelivery(ctx, userID, nil)
}

func (s *IdentityProfileBindingApplicationService) validateTargetIdentityForDelivery(ctx context.Context, userID string, prospectiveTarget *identitymodel.IdentityUser) (string, error) {
	if userID == "" || s.dependencies.Identity == nil {
		return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_target_invalid")
	}
	if prospectiveTarget != nil && strings.TrimSpace(prospectiveTarget.ID) == userID && prospectiveTarget.Status == identitymodel.IdentityStatusActive {
		return userID, nil
	}
	user, found, err := s.dependencies.Identity.FindUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive {
		return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_target_invalid")
	}
	return user.ID, nil
}

func (s *IdentityProfileBindingApplicationService) verifyProfileClaim(ctx context.Context, extension identitymodel.IdentityProfileExtension, record map[string]any, workspaceID, userID, proofType, proofValue string) error {
	var proof identitymodel.IdentityProfileClaimProof
	for _, candidate := range extension.BindingLifecycle.ClaimProofs {
		if strings.TrimSpace(candidate.Type) == proofType {
			proof = candidate
			break
		}
	}
	if proof.Type == "" || proofValue == "" || s.dependencies.Identity == nil {
		return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
	}
	profileValue := identityProfileBindingRecordString(record[proof.FieldKey])
	if profileValue == "" || !identityProfileClaimValueEqual(proofType, profileValue, proofValue) {
		return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
	}
	user, found, err := s.dependencies.Identity.FindUser(ctx, userID)
	if err != nil {
		return err
	}
	if !found || user.Status != identitymodel.IdentityStatusActive {
		return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_identity_invalid")
	}
	switch proofType {
	case "email":
		if !identityProfileClaimValueEqual(proofType, user.Email, proofValue) {
			return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
		}
	case "phone":
		if !identityProfileClaimValueEqual(proofType, user.Phone, proofValue) {
			return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
		}
	case "external_idp_subject":
		if s.dependencies.ExternalClaims == nil {
			return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
		}
		verified, verifyErr := s.dependencies.ExternalClaims.IdentityUserHasExternalSubject(ctx, workspaceID, userID, proofType, proofValue)
		if verifyErr != nil {
			return verifyErr
		}
		if !verified {
			return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
		}
	default:
		return profileBindingError(apperror.KindForbidden, "backend.identity.profile_claim_proof_invalid")
	}
	return nil
}

func (s *IdentityProfileBindingApplicationService) profileBindingDefinition(objectKey, bindingKey string) (identitymodel.IdentityProfileExtension, definitionmodel.ObjectSchema, bool) {
	objects := map[string]definitionmodel.ObjectSchema{}
	if s.dependencies.Objects != nil {
		for _, object := range s.dependencies.Objects() {
			objects[object.Key] = object
		}
	}
	if s.dependencies.Extensions != nil {
		for _, extension := range s.dependencies.Extensions() {
			if extension.ObjectKey == objectKey && strings.TrimSpace(extension.BusinessIdentity.Key) == bindingKey {
				object, ok := objects[objectKey]
				return extension, object, ok
			}
		}
	}
	return identitymodel.IdentityProfileExtension{}, definitionmodel.ObjectSchema{}, false
}
