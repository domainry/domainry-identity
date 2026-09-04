package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func (s *AuthDomainService) randomToken() (string, error) {
	reader := rand.Read
	if s != nil && s.readRandomBytes != nil {
		reader = s.readRandomBytes
	}
	return randomTokenFrom(reader)
}

func randomTokenFrom(readRandomBytes func([]byte) (int, error)) (string, error) {
	var raw [32]byte
	n, err := readRandomBytes(raw[:])
	if err != nil {
		return "", fmt.Errorf("read secure random token: %w", err)
	}
	if n != len(raw) {
		return "", fmt.Errorf("read secure random token: short read: %d/%d", n, len(raw))
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *AuthDomainService) randomDigits(length int) (string, error) {
	reader := rand.Read
	if s != nil && s.readRandomBytes != nil {
		reader = s.readRandomBytes
	}
	return randomDigitsFrom(reader, length)
}

func randomDigitsFrom(readRandomBytes func([]byte) (int, error), length int) (string, error) {
	if length <= 0 {
		length = 6
	}
	// Rejection sampling avoids the modulo bias produced by byte%10. Only
	// values below 250 are accepted because 250 is divisible by ten.
	out := make([]byte, 0, length)
	for attempts := 0; len(out) < length && attempts < 128; attempts++ {
		remaining := length - len(out)
		raw := make([]byte, remaining*2)
		if len(raw) < 16 {
			raw = make([]byte, 16)
		}
		n, err := readRandomBytes(raw)
		if err != nil {
			return "", fmt.Errorf("read secure random digits: %w", err)
		}
		if n != len(raw) {
			return "", fmt.Errorf("read secure random digits: short read: %d/%d", n, len(raw))
		}
		for _, value := range raw {
			if value >= 250 {
				continue
			}
			out = append(out, '0'+value%10)
			if len(out) == length {
				return string(out), nil
			}
		}
	}
	return "", fmt.Errorf("read secure random digits: rejection limit exceeded")
}
