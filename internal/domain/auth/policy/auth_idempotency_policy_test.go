package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAuthPasswordMutationReceiptContractExcludesPasswords(t *testing.T) {
	input := AuthPasswordMutationInput{UserID: "user-1", CurrentPassword: "old-secret", NewPassword: "new-secret", MustChangePassword: true}
	fingerprint, err := AuthPasswordMutationFingerprint("auth.change_password", input, []byte("runtime-owned-pepper"))
	if err != nil || fingerprint == "" || strings.Contains(fingerprint, input.CurrentPassword) || strings.Contains(fingerprint, input.NewPassword) {
		t.Fatalf("fingerprint=%q err=%v", fingerprint, err)
	}
	replay, err := json.Marshal(AuthPasswordMutationReplay{OK: true})
	if err != nil || strings.Contains(string(replay), "secret") || string(replay) != `{"ok":true}` {
		t.Fatalf("replay=%s err=%v", replay, err)
	}
}

func TestAuthPasswordMutationFingerprintErrorsAndStability(t *testing.T) {
	input := AuthPasswordMutationInput{UserID: "user-1", CurrentPassword: "old", NewPassword: "new"}
	if _, err := AuthPasswordMutationFingerprint("auth.change_password", input, nil); err == nil {
		t.Fatal("missing pepper must fail")
	}
	first, err := AuthPasswordMutationFingerprint("auth.change_password", input, []byte("pepper"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := AuthPasswordMutationFingerprint("auth.change_password", input, []byte("pepper"))
	if err != nil || second != first {
		t.Fatalf("stable fingerprint = %q/%q, err=%v", first, second, err)
	}
	input.NewPassword = "changed"
	changed, err := AuthPasswordMutationFingerprint("auth.change_password", input, []byte("pepper"))
	if err != nil || changed == first {
		t.Fatalf("changed fingerprint = %q, err=%v", changed, err)
	}
	wantError := errors.New("second digest failed")
	calls := 0
	_, err = authPasswordMutationFingerprint("auth.change_password", input, []byte("pepper"), func(_ []byte, _ string) (string, error) {
		calls++
		if calls == 2 {
			return "", wantError
		}
		return "digest", nil
	})
	if !errors.Is(err, wantError) {
		t.Fatalf("second digest error = %v", err)
	}
}
