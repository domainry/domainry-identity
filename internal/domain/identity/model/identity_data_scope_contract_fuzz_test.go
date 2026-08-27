package identitymodel

import "testing"

func FuzzCanonicalIdentityDataScopeRoundTrip(f *testing.F) {
	for _, seed := range append(AuthoringDataScopeValues(), "all", "owned", "department_and_children", "invalid") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		canonical, ok := CanonicalIdentityDataScope(value)
		if !ok {
			if canonical != "" {
				t.Fatalf("invalid scope %q returned %q", value, canonical)
			}
			return
		}
		roundTrip, roundTripOK := CanonicalIdentityDataScope(string(canonical))
		if !roundTripOK || roundTrip != canonical {
			t.Fatalf("canonical scope did not round-trip: %q -> %q/%v", canonical, roundTrip, roundTripOK)
		}
	})
}
