// Package capability exposes Identity's source-owned capability contract for
// explicit Plane composition. It does not open an Identity application or add
// a second provider lifecycle.
package capability

import (
	"github.com/domainry/domainry-foundation/modulecapability"
	identitysdkadapter "github.com/domainry/domainry-identity/internal/adapter/identitysdk"
)

// Inputs is intentionally empty because Identity's capability contract and
// owner validation rules are source-owned and deterministic.
type Inputs struct{}

// Open returns the exact capability binding used by the operational Identity
// SDK binding.
func Open(Inputs) (*modulecapability.StaticBinding, error) {
	return identitysdkadapter.NewCapabilityBinding()
}
