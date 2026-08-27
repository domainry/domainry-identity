package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

func randomToken() string {
	return randomTokenFrom(rand.Read, time.Now().UnixNano())
}

func randomTokenFrom(readRandomBytes func([]byte) (int, error), currentUnixNano int64) string {
	var raw [32]byte
	if _, err := readRandomBytes(raw[:]); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", currentUnixNano)))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func randomDigits(length int) string {
	return randomDigitsFromToken(randomToken(), length)
}

func randomDigitsFromToken(token string, length int) string {
	if length <= 0 {
		length = 6
	}
	out := make([]byte, 0, length)
	for _, char := range token {
		if char >= '0' && char <= '9' {
			out = append(out, byte(char))
			if len(out) == length {
				return string(out)
			}
		}
	}
	for len(out) < length {
		out = append(out, '0'+byte(len(out)%10))
	}
	return string(out)
}
