// Package saas assembles the standalone Identity service.
package saas

import (
	"context"
	"net/http"

	"github.com/domainry/domainry-identity/internal/platform/config"
	saashttp "github.com/domainry/domainry-identity/internal/transport/http/saas"
)

type Service struct {
	server *saashttp.Server
}

func Open(ctx context.Context, cfg config.Config) (*Service, error) {
	server, err := saashttp.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Service{server: server}, nil
}

func (service *Service) DevelopmentRoutes() http.Handler {
	return saashttp.DevelopmentRoutes(service.server)
}
func (service *Service) PublicRoutes() http.Handler { return saashttp.PublicRoutes(service.server) }
func (service *Service) TenantAdminRoutes() http.Handler {
	return saashttp.TenantAdminRoutes(service.server)
}
func (service *Service) OperationsRoutes() http.Handler {
	return saashttp.OperationsRoutes(service.server)
}

func (service *Service) Close(ctx context.Context) error {
	if service == nil || service.server == nil {
		return nil
	}
	return service.server.CloseContext(ctx)
}
