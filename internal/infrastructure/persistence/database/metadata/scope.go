package metadata

import (
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func requireMetadataInstallationScope(scope identitymodel.SystemScope) error {
	if _, err := identitymodel.NewSystemQueryScope(scope); err != nil {
		return err
	}
	if scope.Kind != identitymodel.SystemScopeInstallation {
		return fmt.Errorf("metadata installation scope is required")
	}
	return nil
}

func requireMetadataWorkspaceID(explicit, embedded string) (string, error) {
	workspaceID, err := identitymodel.NewWorkspaceID(explicit)
	if err != nil {
		return "", fmt.Errorf("metadata workspace: %w", err)
	}
	embedded = strings.TrimSpace(embedded)
	if len(embedded) > 0 && strings.Compare(workspaceID.String(), embedded) != 0 {
		return "", fmt.Errorf("metadata workspace mismatch: explicit %q does not match payload %q", workspaceID.String(), embedded)
	}
	return workspaceID.String(), nil
}
