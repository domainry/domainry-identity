package module

import (
	"net/http"

	identitymanagement "github.com/domainry/domainry-identity-sdk/management"
)

type moduleManagementSurface struct {
	handler http.Handler
	routes  []identitymanagement.Route
}

func (*moduleManagementSurface) ContractVersion() string {
	return identitymanagement.ContractVersion
}

func (surface *moduleManagementSurface) Routes() []identitymanagement.Route {
	if surface == nil {
		return nil
	}
	return append([]identitymanagement.Route(nil), surface.routes...)
}

func (surface *moduleManagementSurface) Handler() http.Handler {
	if surface == nil {
		return nil
	}
	return surface.handler
}

var _ identitymanagement.Surface = (*moduleManagementSurface)(nil)
