package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/domainry/domainry-foundation/processhost"
	saasassembly "github.com/domainry/domainry-identity/internal/assembly/saas"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

var identityVersion = "dev"
var processExit = os.Exit

func main() {
	processExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("domainry-identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: domainry-identity")
		_, _ = fmt.Fprintln(stderr)
		_, _ = fmt.Fprintln(stderr, "Identity backend configuration is supplied through environment variables.")
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, _ = fmt.Fprintln(stdout, "Usage: domainry-identity")
		_, _ = fmt.Fprintln(stdout)
		_, _ = fmt.Fprintln(stdout, "Identity backend configuration is supplied through environment variables.")
		return 0
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "domainry-identity: unexpected arguments: %v\n", flags.Args())
		flags.Usage()
		return 2
	}
	if err := serve(); err != nil {
		_, _ = fmt.Fprintln(stderr, "domainry-identity: process failed")
		return 1
	}
	return 0
}

func serve() (runErr error) {
	lifecycleCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	observability, err := processhost.Open(lifecycleCtx, processhost.Config{ServiceName: "domainry-identity", ServiceVersion: identityVersion})
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	defer func() { runErr = observability.Finish(context.Background(), nil, runErr) }()

	cfg, _, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	cfg.ServiceVersion = identityVersion
	if err := cfg.ValidateSaaSDeployment(); err != nil {
		return fmt.Errorf("validate SaaS deployment: %w", err)
	}
	identityServer, err := saasassembly.Open(lifecycleCtx, cfg)
	if err != nil {
		return fmt.Errorf("initialize Identity backend: %w", err)
	}

	listeners := identityHTTPListeners(cfg, identityServer, observability)
	serveErr := make(chan error, len(listeners))
	observability.Started(lifecycleCtx, map[string]any{"listener_count": len(listeners)})
	for _, listener := range listeners {
		listener := listener
		go func() { serveErr <- listener.server.ListenAndServe() }()
	}

	select {
	case err := <-serveErr:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
		defer cancel()
		shutdownErr := shutdownIdentityListeners(shutdownCtx, listeners)
		closeErr := identityServer.Close(shutdownCtx)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		return errors.Join(err, shutdownErr, closeErr)
	case <-lifecycleCtx.Done():
		observability.Stopping(context.Background(), map[string]any{"reason": "signal"})
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
		defer cancel()
		return errors.Join(shutdownIdentityListeners(shutdownCtx, listeners), identityServer.Close(shutdownCtx))
	}
}

type identityHTTPListener struct {
	group  string
	server *http.Server
}

func identityHTTPListeners(cfg config.Config, identityServer *saasassembly.Service, observability *processhost.Host) []identityHTTPListener {
	wrap := func(group string, handler http.Handler) http.Handler {
		if observability == nil {
			return handler
		}
		return observability.Handler(group, handler)
	}
	if cfg.IsProduction() {
		return []identityHTTPListener{
			{group: "public", server: newIdentityHTTPServer(cfg.HTTPPublicAddr, wrap("public", identityServer.PublicRoutes()), cfg)},
			{group: "management", server: newIdentityHTTPServer(cfg.HTTPManagementAddr, wrap("management", identityServer.ManagementRoutes()), cfg)},
			{group: "ops", server: newIdentityHTTPServer(cfg.HTTPOpsAddr, wrap("ops", identityServer.OperationsRoutes()), cfg)},
		}
	}
	return []identityHTTPListener{{group: "development", server: newIdentityHTTPServer(cfg.HTTPAddr(), wrap("public", identityServer.DevelopmentRoutes()), cfg)}}
}

func newIdentityHTTPServer(address string, handler http.Handler, cfg config.Config) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    cfg.HTTPMaxHeaderBytes,
	}
}

func shutdownIdentityListeners(ctx context.Context, listeners []identityHTTPListener) error {
	errorsByListener := make([]error, 0, len(listeners))
	for _, listener := range listeners {
		if listener.server != nil {
			errorsByListener = append(errorsByListener, listener.server.Shutdown(ctx))
		}
	}
	return errors.Join(errorsByListener...)
}
