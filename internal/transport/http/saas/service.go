// Package saas exposes the standalone Identity HTTP transport boundary.
package saas

import (
	"context"
	"net/http"

	"github.com/domainry/domainry-identity/internal/platform/config"
	httpserver "github.com/domainry/domainry-identity/internal/transport/http/server"
)

type Server = httpserver.Server

func New(ctx context.Context, cfg config.Config) (*Server, error) {
	return httpserver.New(ctx, cfg)
}

func DevelopmentRoutes(server *Server) http.Handler { return server.Routes() }
func PublicRoutes(server *Server) http.Handler      { return server.PublicRoutes() }
func ManagementRoutes(server *Server) http.Handler  { return server.ManagementRoutes() }
func OperationsRoutes(server *Server) http.Handler  { return server.OperationsRoutes() }
