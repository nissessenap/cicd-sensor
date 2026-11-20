package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// Secrets are the reconciler inputs that must not live in the config file.
type Secrets struct {
	PostgresDSN string
}

// Validate reports every missing secret.
func (s Secrets) Validate() error {
	if s.PostgresDSN == "" {
		return errors.New("postgres DSN is required")
	}
	return nil
}

// Run starts the reconciler and blocks until ctx is done or a component
// fails.
func Run(ctx context.Context, logger *slog.Logger, cfg Config, secrets Secrets) error {
	if err := secrets.Validate(); err != nil {
		return err
	}
	store, err := OpenStore(ctx, secrets.PostgresDSN)
	if err != nil {
		return err
	}
	defer store.Close()

	metrics := &Metrics{}
	loop := NewReconciler(ReconcilerConfig{
		Store:       store,
		Expect:      cfg.Expect,
		GracePeriod: cfg.GracePeriod,
		Retention:   cfg.Retention,
		Metrics:     metrics,
		Logger:      logger,
	})

	listener, err := net.Listen("tcp", cfg.BindAddress())
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.BindAddress(), err)
	}
	server := &http.Server{
		Handler:           newHTTPHandler(store, metrics),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return ignoreCanceled(loop.Run(ctx, cfg.ReconcileInterval)) })
	group.Go(func() error {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})
	return group.Wait()
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// pinger reports whether the reconciler's database is reachable.
type pinger interface {
	Ping(ctx context.Context) error
}

// newHTTPHandler exposes exactly the reconciler's public surface.
func newHTTPHandler(db pinger, metrics *Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /metrics", metrics)
	return mux
}
