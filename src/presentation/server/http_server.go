package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"reverse-proxy-mac/src/domain/logger"
)

const (
	defaultReadTimeout     = 5 * time.Second
	defaultWriteTimeout    = 10 * time.Second
	defaultIdleTimeout     = 120 * time.Second
	defaultShutdownTimeout = 30 * time.Second
)

// HealthChecker is an interface for components that can report their health status.
type HealthChecker interface {
	IsHealthy(ctx context.Context) bool
}

// CacheRefresher is an interface for components that support force-refreshing their cache.
type CacheRefresher interface {
	ForceRefresh(ctx context.Context) error
}

// HTTPServer provides HTTP endpoints for health checks and Prometheus metrics.
type HTTPServer struct {
	server         *http.Server
	logger         logger.Logger
	host           string
	port           int
	healthCheckers map[string]HealthChecker
	cacheRefresher CacheRefresher
	mu             sync.RWMutex
	running        bool
}

// NewHTTPServer creates a new HTTP server for health and metrics endpoints.
func NewHTTPServer(host string, port int, log logger.Logger) *HTTPServer {
	return &HTTPServer{
		host:           host,
		port:           port,
		logger:         log,
		healthCheckers: make(map[string]HealthChecker),
	}
}

// RegisterCacheRefresher registers a cache refresher for the /cache/refresh endpoint.
func (s *HTTPServer) RegisterCacheRefresher(refresher CacheRefresher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheRefresher = refresher
}

// RegisterHealthChecker registers a named health checker component.
func (s *HTTPServer) RegisterHealthChecker(name string, checker HealthChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthCheckers[name] = checker
}

// Start starts the HTTP server.
func (s *HTTPServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if server is already running
	if s.running {
		return fmt.Errorf("HTTP server is already running")
	}

	// Create mux and register endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/health/live", s.handleLiveness)
	mux.HandleFunc("/health/ready", s.handleReadiness)
	mux.HandleFunc("/cache/refresh", s.handleCacheRefresh)
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer,
		promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		}),
	))

	// Create server with configuration
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  defaultReadTimeout,
		WriteTimeout: defaultWriteTimeout,
		IdleTimeout:  defaultIdleTimeout,
	}

	s.running = true

	// Start server in background goroutine
	go func() {
		s.logger.Info(ctx, "HTTP server starting", map[string]interface{}{"address": addr})
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error(context.Background(), "HTTP server error", map[string]interface{}{"error": err.Error()})
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server.
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If server is not running, nothing to do
	if !s.running {
		return nil
	}

	s.logger.Info(ctx, "Stopping HTTP server", nil)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, defaultShutdownTimeout)
	defer cancel()

	// Shutdown the server
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Error(ctx, "HTTP server shutdown error", map[string]interface{}{"error": err.Error()})
		return err
	}

	s.running = false
	s.logger.Info(ctx, "HTTP server stopped", nil)
	return nil
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status     string                 `json:"status"`
	Components map[string]string      `json:"components,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// handleHealth handles the /health endpoint - comprehensive health check.
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get a copy of health checkers
	s.mu.RLock()
	checkers := make(map[string]HealthChecker, len(s.healthCheckers))
	for k, v := range s.healthCheckers {
		checkers[k] = v
	}
	s.mu.RUnlock()

	// Create response structure
	response := HealthResponse{
		Status:     "healthy",
		Components: make(map[string]string),
	}

	// Check all components
	allHealthy := true
	for name, checker := range checkers {
		if checker.IsHealthy(ctx) {
			response.Components[name] = "healthy"
		} else {
			response.Components[name] = "unhealthy"
			allHealthy = false
		}
	}

	// Set status code based on health
	if !allHealthy {
		response.Status = "unhealthy"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(ctx, "Failed to encode health response", map[string]interface{}{"error": err.Error()})
	}
}

// handleLiveness handles the /health/live endpoint - basic liveness probe.
// Returns 200 OK if the service is running.
func (s *HTTPServer) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Create liveness response
	response := HealthResponse{
		Status: "alive",
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(r.Context(), "Failed to encode liveness response", map[string]interface{}{"error": err.Error()})
	}
}

// handleReadiness handles the /health/ready endpoint - readiness probe.
// Returns 200 OK if all registered health checkers report healthy.
func (s *HTTPServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get a copy of health checkers
	s.mu.RLock()
	checkers := make(map[string]HealthChecker, len(s.healthCheckers))
	for k, v := range s.healthCheckers {
		checkers[k] = v
	}
	s.mu.RUnlock()

	// Create response structure
	response := HealthResponse{
		Status:     "ready",
		Components: make(map[string]string),
	}

	// Check all components for readiness
	allReady := true
	for name, checker := range checkers {
		if checker.IsHealthy(ctx) {
			response.Components[name] = "ready"
		} else {
			response.Components[name] = "not_ready"
			allReady = false
		}
	}

	// Set status code based on readiness
	if !allReady {
		response.Status = "not_ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error(ctx, "Failed to encode readiness response", map[string]interface{}{"error": err.Error()})
	}
}

// CacheRefreshResponse represents the response for the cache refresh endpoint.
type CacheRefreshResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// handleCacheRefresh handles the POST /cache/refresh endpoint — triggers an
// immediate reload of the in-memory cache from LDAP.
func (s *HTTPServer) handleCacheRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(CacheRefreshResponse{
			Status:  "error",
			Message: "only POST method is allowed",
		})
		return
	}

	s.mu.RLock()
	refresher := s.cacheRefresher
	s.mu.RUnlock()

	if refresher == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(CacheRefreshResponse{
			Status:  "error",
			Message: "cache refresher is not registered",
		})
		return
	}

	s.logger.Info(ctx, "Cache force refresh triggered via HTTP endpoint", nil)

	if err := refresher.ForceRefresh(ctx); err != nil {
		s.logger.Error(ctx, "Cache force refresh failed", map[string]interface{}{"error": err.Error()})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(CacheRefreshResponse{
			Status:  "error",
			Message: fmt.Sprintf("cache refresh failed: %s", err.Error()),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(CacheRefreshResponse{
		Status:  "ok",
		Message: "cache refreshed successfully",
	})
}
