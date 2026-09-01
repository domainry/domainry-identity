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
		!identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.profile_bindings.command") {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindForbidden, "backend.identity.profile_binding_manage_required")
	}
	request.ObjectKey = strings.TrimSpace(request.ObjectKey)
	request.ProfileID = strings.TrimSpace(request.ProfileID)
	request.BindingKey = strings.TrimSpace(request.BindingKey)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.ObjectKey == "" || request.ProfileID == "" || request.BindingKey == "" || request.IdempotencyKey == "" || request.ExpectedVersion < 0 {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_command_invalid")
	}
	extension, object, found := s.profileBindingDefinition(request.ObjectKey, request.BindingKey)
	if !found {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindNotFound, "backend.identity.profile_binding_definition_not_found")
	}
	if s.dependencies.Repository == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	mutation := identitymodel.IdentityProfileBindingMutation{
		WorkspaceID: principal.WorkspaceID, BindingKey: request.BindingKey, ObjectKey: request.ObjectKey, ProfileID: request.ProfileID,
		IdentityField: extension.IdentityRelationField, Operation: operation, IdentityUserID: profileBindingRequestedTarget(request, operation, principal.UserID),
		InvitationChannel: strings.TrimSpace(request.InvitationChannel), ClaimProofType: strings.TrimSpace(request.ClaimProofType),
		Reason: strings.TrimSpace(request.Reason), ExpectedVersion: request.ExpectedVersion, IdempotencyKey: request.IdempotencyKey, ActorID: principal.UserID,
		ApprovalID: strings.TrimSpace(request.ApprovalID),
	}
	if s.dependencies.SystemRoles != nil {
		resolvedRoleIDs, roleErr := s.dependencies.SystemRoles.ResolveIdentityProfileSystemRoleIDs(ctx, request.BindingKey)
		if roleErr != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, roleErr
		}
		mutation.SystemManagedRoleIDs = resolvedRoleIDs
	}
	mutation.RequestFingerprint = identityProfileBindingFingerprint(mutation)
	if receipt, found, receiptErr := s.dependencies.Repository.GetIdentityProfileBindingReceipt(ctx, mutation); receiptErr != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, receiptErr
	} else if found {
		if receipt.RequestFingerprint != mutation.RequestFingerprint {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindConflict, "backend.idempotency_key_reused")
		}
		receipt.Replayed = true
		return receipt, nil
	}
	if s.dependencies.Records == nil {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindInternal, "backend.identity.profile_binding_unavailable")
	}
	record, recordFound, err := s.dependencies.Records.GetIdentityProfileBindingRecord(ctx, principal.WorkspaceID, object, request.ProfileID)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if !recordFound {
		return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindNotFound, "backend.identity.profile_not_found")
	}
	currentUserID := identityProfileBindingRecordString(record[extension.IdentityRelationField])
	targetUserID, err := s.validateProfileBindingCommand(ctx, request, operation, extension, record, principal)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	mutation.IdentityUserID = targetUserID
	receipt, err := s.dependencies.Repository.ExecuteIdentityProfileBindingMutation(ctx, mutation)
	if err != nil {
		return identitymodel.IdentityProfileBindingReceipt{}, err
	}
	if operation == identitymodel.IdentityProfileBindingRebind && extension.BindingLifecycle.RebindRevokesSessions {
		if s.dependencies.SessionRevoker == nil {
			return identitymodel.IdentityProfileBindingReceipt{}, profileBindingError(apperror.KindInternal, "backend.identity.profile_rebind_session_revocation_unavailable")
		}
		if err := s.dependencies.SessionRevoker.RevokeIdentityProfileSessions(ctx, principal.WorkspaceID, currentUserID, "identity_profile_rebind"); err != nil {
			return identitymodel.IdentityProfileBindingReceipt{}, err
		}
	}
	return receipt, nil
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
	canManage := identitycontract.IdentityRoleHasPermissionKey(principal.Role, "identity.profile_bindings.get")
	if !canManage && strings.TrimSpace(binding.IdentityUserID) != strings.TrimSpace(principal.UserID) {
		return identitymodel.IdentityProfileBinding{}, false, profileBindingError(apperror.KindForbidden, "backend.identity.profile_binding_read_denied")
	}
	return binding, true, nil
}

func (s *IdentityProfileBindingApplicationService) validateProfileBindingCommand(ctx context.Context, request IdentityProfileBindingCommandRequest, operation identitymodel.IdentityProfileBindingOperation, extension identitymodel.IdentityProfileExtension, record map[string]any, principal identitymodel.Principal) (string, error) {
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
		return s.validateTargetIdentity(ctx, strings.TrimSpace(request.IdentityUserID))
	case identitymodel.IdentityProfileBindingRebind:
		if currentUserID == "" || strings.TrimSpace(request.Reason) == "" {
			return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_rebind_reason_required")
		}
		targetUserID, err := s.validateTargetIdentity(ctx, strings.TrimSpace(request.IdentityUserID))
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
	if userID == "" || s.dependencies.Identity == nil {
		return "", profileBindingError(apperror.KindBadRequest, "backend.identity.profile_binding_target_invalid")
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
