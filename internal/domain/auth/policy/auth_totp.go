package policy

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// MatchTOTP implements RFC 6238 with the interoperable SHA-1, six-digit,
// 30-second profile. The caller must atomically persist the returned step.
func MatchTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 20 {
		return 0, false
	}
	current := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		step := current + offset
		if step < 0 || step <= lastStep {
			continue
		}
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step))
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(counter[:])
		digest := mac.Sum(nil)
		start := digest[len(digest)-1] & 15
		value := binary.BigEndian.Uint32(digest[start:start+4]) & 0x7fffffff
		expected := fmt.Sprintf("%06d", value%1000000)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
