package schema

import sharedoperation "github.com/domainry/domainry-foundation/operation"

// OperationsKernelTables reports the shared Foundation-owned physical tables
// that Identity consumes. Their definitions and migrations live only in the
// Foundation operation package.
func OperationsKernelTables() []string { return sharedoperation.OwnedTables() }
