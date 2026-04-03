package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server exposes Prometheus metrics over HTTP.
type Server struct {
	srv    *http.Server
	logger *slog.Logger
}

// NewServer creates a metrics HTTP server that serves the given path on the
// specified listen address (e.g. ":9090").
func NewServer(listen, path string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())

	return &Server{
		srv: &http.Server{
			Addr:              listen,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// Start begins serving metrics in the background. It returns immediately
// after the listener is established.
func (s *Server) Start(_ context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("metrics server listening", "addr", ln.Addr().String())

	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server error", "err", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the metrics server.
func (s *Server) Stop(_ context.Context) error {
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.logger.Info("metrics server shutting down")
	return s.srv.Shutdown(shutCtx)
}

// Name returns the component name used for logging and lifecycle management.
func (s *Server) Name() string {
	return "metrics-server"
}
