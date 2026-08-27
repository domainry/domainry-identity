package policy

import "testing"

func TestIdentityAnonymizedSubjectIsStableScopedAndNonIdentifying(t *testing.T) {
	first := IdentityAnonymizedSubject("workspace-a", "user-1")
	if first != IdentityAnonymizedSubject("workspace-a", "user-1") {
		t.Fatal("anonymization is not stable")
	}
	if first == IdentityAnonymizedSubject("workspace-b", "user-1") {
		t.Fatal("anonymization token crossed workspace")
	}
	if first.Name == "" || first.Email == "" || first.Token == "user-1" {
		t.Fatalf("invalid anonymization %#v", first)
	}
}
