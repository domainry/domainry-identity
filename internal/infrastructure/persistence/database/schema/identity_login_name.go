package schema

import (
	"context"
)

// The fresh schema declares login_name_key directly. The global unique index
// intentionally remains installation-scoped because an unscoped login must
// resolve to exactly one Workspace before authentication can proceed.
func ensureIdentityGlobalLoginNames(ctx context.Context, s Store) error {
	return s.CreateIndexIfMissing(ctx, "_identity_users", "uniq_identity_users_login_name", true, "login_name_key")
}
