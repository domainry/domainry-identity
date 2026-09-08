package policy

import (
	"testing"
	"time"
)

func TestTOTPRFC6238SHA1VectorsAndReplay(t *testing.T) {
	const key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// RFC 6238 Appendix B SHA-1 vectors, reduced to the six-digit profile.
	for _, vector := range []struct {
		unix int64
		code string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		now := time.Unix(vector.unix, 0)
		step, ok := MatchTOTP(key, vector.code, now, -1)
		if !ok || step != vector.unix/30 {
			t.Fatalf("vector %d failed", vector.unix)
		}
		if _, ok := MatchTOTP(key, vector.code, now, step); ok {
			t.Fatal("replayed time step accepted")
		}
	}
	for _, code := range []string{"", "28708", "2870820", "abcdef", "２８７０８２"} {
		if _, ok := MatchTOTP(key, code, time.Unix(59, 0), -1); ok {
			t.Fatalf("invalid code accepted: %q", code)
		}
	}
	if _, ok := MatchTOTP(key, "287082", time.Unix(59+90, 0), -1); ok {
		t.Fatal("expired code accepted")
	}
}
