package rls

import (
	"context"
	"database/sql"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Profile struct{}

func NewProfile() Profile { return Profile{} }

func (Profile) WorkspaceRLSSupported() bool { return false }
func (Profile) ApplyWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) error {
	return nil
}
func (Profile) InspectWorkspaceRLS(context.Context, *sql.DB, ormdialect.Renderer, string, string, string) (driver.WorkspaceRLSStatus, error) {
	return driver.WorkspaceRLSStatus{}, nil
}
