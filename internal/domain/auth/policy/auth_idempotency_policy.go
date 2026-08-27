package policy

import (
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
)

const (
	AuthMutationSuccessReceiptRetention = 30 * 24 * time.Hour
	AuthMutationFailureReceiptRetention = 7 * 24 * time.Hour
)

type AuthPasswordMutationInput struct {
	UserID             string
	CurrentPassword    string
	NewPassword        string
	MustChangePassword bool
}

type AuthPasswordMutationReplay struct {
	OK bool `json:"ok"`
}

func AuthPasswordMutationFingerprint(useCase string, input AuthPasswordMutationInput, pepper []byte) (string, error) {
	return authPasswordMutationFingerprint(useCase, input, pepper, idempotency.SensitiveValueDigest)
}

func authPasswordMutationFingerprint(useCase string, input AuthPasswordMutationInput, pepper []byte, digest func([]byte, string) (string, error)) (string, error) {
	currentDigest, err := digest(pepper, input.CurrentPassword)
	if err != nil {
		return "", err
	}
	newDigest, err := digest(pepper, input.NewPassword)
	if err != nil {
		return "", err
	}
	return idempotency.Fingerprint(idempotency.FingerprintInput{
		UseCase: useCase, ResourceType: "identity_user", TargetID: input.UserID,
		Payload: map[string]any{"current_password_digest": currentDigest, "new_password_digest": newDigest, "must_change_password": input.MustChangePassword},
	})
}
