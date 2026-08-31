package module

import (
	"net/http"

	identityhttpapi "github.com/domainry/domainry-identity-sdk/httpapi"
)

type moduleHTTPSurface struct {
	name    string
	handler http.Handler
	routes  []identityhttpapi.Route
}

func (*moduleHTTPSurface) ContractVersion() string {
	return identityhttpapi.ContractVersion
}

func (*moduleHTTPSurface) Owner() string { return "identity" }

func (surface *moduleHTTPSurface) Name() string {
	if surface == nil {
		return ""
	}
	return surface.name
}

func (surface *moduleHTTPSurface) Routes() []identityhttpapi.Route {
	if surface == nil {
		return nil
	}
	routes := make([]identityhttpapi.Route, len(surface.routes))
	for index, route := range surface.routes {
		routes[index] = route
		routes[index].Exposures = append([]identityhttpapi.Exposure(nil), route.Exposures...)
	}
	return routes
}

func (surface *moduleHTTPSurface) Handler() http.Handler {
	if surface == nil {
		return nil
	}
	return surface.handler
}

var _ identityhttpapi.Surface = (*moduleHTTPSurface)(nil)
