package service

import (
	"errors"
	"testing"
)

func TestRandomTokenSources(t *testing.T) {
	success := randomTokenFrom(func(buffer []byte) (int, error) {
		for index := range buffer {
			buffer[index] = byte(index + 1)
		}
		return len(buffer), nil
	}, 1)
	if success == "" {
		t.Fatal("random token must not be blank")
	}
	fallback := randomTokenFrom(func([]byte) (int, error) {
		return 0, errors.New("random source failed")
	}, 123)
	if fallback == "" || fallback == success {
		t.Fatalf("unexpected fallback token %q", fallback)
	}
}

func TestRandomDigitExtraction(t *testing.T) {
	if digits := randomDigitsFromToken("a1b2", 2); digits != "12" {
		t.Fatalf("unexpected extracted digits %q", digits)
	}
	if digits := randomDigitsFromToken("/A", 3); digits != "012" {
		t.Fatalf("unexpected digit fallback %q", digits)
	}
	if digits := randomDigitsFromToken("12", 0); digits != "122345" {
		t.Fatalf("unexpected default-length digits %q", digits)
	}
	if digits := randomDigits(1); len(digits) != 1 {
		t.Fatalf("random digit generator returned %q", digits)
	}
}
