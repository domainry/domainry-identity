// Package capability exposes Identity's source-owned capability contract for
// explicit Plane composition. It does not open an Identity application or add
// a second provider lifecycle.
package capability

import (
	"github.com/domainry/domainry-foundation/modulecapability"
)

// Inputs carries source-owned alternative implementation categories selected by
// the release composition root. Identity still owns the logical authoring and
// validation contract; an adapter owns the facts about when and how it can
// replace the canonical module or SaaS implementation.
type Inputs struct {
	AdapterCategories []modulecapability.CategoryDocument
}

// Open returns the exact capability binding used by the operational Identity
// SDK binding.
func Open(inputs Inputs) (*modulecapability.StaticBinding, error) {
	return openContract(inputs)
}
