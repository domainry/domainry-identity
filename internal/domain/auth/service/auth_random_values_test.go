package service

import (
	"errors"
	"testing"
)

func TestRandomTokenSources(t *testing.T) {
	success, err := randomTokenFrom(func(buffer []byte) (int, error) {
		for index := range buffer {
			buffer[index] = byte(index + 1)
		}
		return len(buffer), nil
	})
	if err != nil || success == "" {
		t.Fatalf("random token=%q err=%v", success, err)
	}
	if fallback, err := randomTokenFrom(func([]byte) (int, error) {
		return 0, errors.New("random source failed")
	}); err == nil || fallback != "" {
		t.Fatalf("entropy failure did not fail closed: token=%q err=%v", fallback, err)
	}
	if short, err := randomTokenFrom(func(buffer []byte) (int, error) {
		return len(buffer) - 1, nil
	}); err == nil || short != "" {
		t.Fatalf("short entropy read did not fail closed: token=%q err=%v", short, err)
	}
}

func TestRandomDigitsUseUnbiasedSecureBytes(t *testing.T) {
	reader := func(buffer []byte) (int, error) {
		for index := range buffer {
			buffer[index] = byte(index)
		}
		return len(buffer), nil
	}
	if digits, err := randomDigitsFrom(reader, 6); err != nil || digits != "012345" {
		t.Fatalf("random digits=%q err=%v", digits, err)
	}
	if digits, err := randomDigitsFrom(reader, 0); err != nil || len(digits) != 6 {
		t.Fatalf("default random digits=%q err=%v", digits, err)
	}
	if digits, err := randomDigitsFrom(func([]byte) (int, error) {
		return 0, errors.New("random source failed")
	}, 6); err == nil || digits != "" {
		t.Fatalf("digit entropy failure did not fail closed: digits=%q err=%v", digits, err)
	}
	if digits, err := randomDigitsFrom(func(buffer []byte) (int, error) {
		for index := range buffer {
			buffer[index] = 255
		}
		return len(buffer), nil
	}, 6); err == nil || digits != "" {
		t.Fatalf("rejection exhaustion did not fail closed: digits=%q err=%v", digits, err)
	}
}
