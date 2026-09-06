package moduleassembly

import "testing"

func TestWorkspaceBootstrapVolatileCredentialReplacementAndDiscardDoNotAccumulate(t *testing.T) {
	binding := &moduleBinding{}
	binding.storeWorkspaceBootstrapCredential("receipt", "workspace", "first@example.test", []byte("FirstPassword1!"))
	first := binding.bootstrapCredentials["receipt"]
	binding.storeWorkspaceBootstrapCredential("receipt", "workspace", "second@example.test", []byte("SecondPassword1!"))
	if len(binding.bootstrapCredentials) != 1 {
		t.Fatalf("pending credentials=%d", len(binding.bootstrapCredentials))
	}
	binding.expireWorkspaceBootstrapCredential("receipt", first)
	if binding.bootstrapCredentials["receipt"] == nil {
		t.Fatal("stale expiry removed the replacement credential")
	}
	for _, value := range first.password {
		if value != 0 {
			t.Fatal("replaced volatile credential was not zeroed")
		}
	}
	current := binding.bootstrapCredentials["receipt"]
	binding.discardWorkspaceBootstrapCredential("receipt")
	if len(binding.bootstrapCredentials) != 0 {
		t.Fatalf("pending credentials after discard=%d", len(binding.bootstrapCredentials))
	}
	for _, value := range current.password {
		if value != 0 {
			t.Fatal("discarded volatile credential was not zeroed")
		}
	}
}
