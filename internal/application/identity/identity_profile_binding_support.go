package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityProfileBindingOperationAllowed(operation identitymodel.IdentityProfileBindingOperation) bool {
	return map[identitymodel.IdentityProfileBindingOperation]bool{
		identitymodel.IdentityProfileBindingInvite: true, identitymodel.IdentityProfileBindingClaim: true,
		identitymodel.IdentityProfileBindingBind: true, identitymodel.IdentityProfileBindingRebind: true,
		identitymodel.IdentityProfileBindingUnlink: true,
	}[operation]
}

func identityProfileBindingStringAllowed(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target && target != "" {
			return true
		}
	}
	return false
}

func identityProfileClaimValueEqual(proofType, left, right string) bool {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if proofType == "phone" {
		replacer := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "")
		left, right = replacer.Replace(left), replacer.Replace(right)
	}
	return left != "" && strings.EqualFold(left, right)
}

func identityProfileBindingRecordString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func identityProfileBindingFingerprint(mutation identitymodel.IdentityProfileBindingMutation) string {
	value := struct {
		BindingKey, ObjectKey, ProfileID, IdentityField, Operation, IdentityUserID, InvitationChannel, ClaimProofType, Reason, ApprovalID string
		ExpectedVersion                                                                                                                   int64
		SystemManagedRoleIDs                                                                                                              []string
	}{
		mutation.BindingKey, mutation.ObjectKey, mutation.ProfileID, mutation.IdentityField, string(mutation.Operation),
		mutation.IdentityUserID, mutation.InvitationChannel, mutation.ClaimProofType, mutation.Reason, mutation.ApprovalID, mutation.ExpectedVersion, identityUniqueSortedStrings(mutation.SystemManagedRoleIDs),
	}
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func identityUniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func profileBindingError(kind apperror.ErrorKind, code string) error {
	return &apperror.AppError{Kind: kind, Code: code}
}
