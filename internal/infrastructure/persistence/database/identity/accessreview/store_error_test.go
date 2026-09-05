package accessreview

import (
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
)

func TestNormalizeAccessReviewCreateError(t *testing.T) {
	duplicate := errors.New("UNIQUE constraint failed: _identity_access_reviews.workspace_id, _identity_access_reviews.id")
	if code := apperror.CodeOf(normalizeAccessReviewCreateError(duplicate)); code != "backend.identity.access_review_exists" {
		t.Fatalf("duplicate code=%q", code)
	}
	probe := errors.New("storage unavailable")
	if got := normalizeAccessReviewCreateError(probe); !errors.Is(got, probe) {
		t.Fatalf("non-duplicate error changed: %v", got)
	}
	if normalizeAccessReviewCreateError(nil) != nil {
		t.Fatal("nil error changed")
	}
}
