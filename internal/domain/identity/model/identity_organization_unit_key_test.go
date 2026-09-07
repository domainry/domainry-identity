package identitymodel

import "testing"

func TestIdentityOrganizationUnitSiblingKeyMatchesDomainNameUniqueness(t *testing.T) {
	parentA, parentB := "parent-a", "parent-b"
	for _, pair := range [][2]string{
		{" Sales ", "sales"},
		{"Σ", "ς"},
		{"Kelvin", "kelvin"},
	} {
		left := IdentityOrganizationUnitSiblingKey(&parentA, pair[0])
		right := IdentityOrganizationUnitSiblingKey(&parentA, pair[1])
		if left != right {
			t.Fatalf("EqualFold sibling names produced different keys: %q %q", pair[0], pair[1])
		}
	}
	if IdentityOrganizationUnitSiblingKey(&parentA, "Sales") == IdentityOrganizationUnitSiblingKey(&parentB, "Sales") {
		t.Fatal("different parents produced the same sibling key")
	}
	if IdentityOrganizationUnitSiblingKey(nil, "Sales") != IdentityOrganizationUnitSiblingKey(nil, "sales") {
		t.Fatal("root sibling names did not use EqualFold semantics")
	}
}
