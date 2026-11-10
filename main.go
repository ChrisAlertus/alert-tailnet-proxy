// Command alert-tailnet-proxy joins a tailnet as its own node and, for now,
// replies to every HTTP request with the caller's Tailscale identity.
//
// Milestone 1: prove we can (a) join the tailnet with tsnet and
// (b) identify each caller with WhoIs. The LLM proxy comes later.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

func main() {
	hostname := flag.String("hostname", "llm-proxy", "node name to register on the tailnet")
	stateDir := flag.String("state-dir", "", "directory for tsnet state (default: under os.UserConfigDir)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// ctx is cancelled when we receive Ctrl-C (SIGINT) or SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, *hostname, *stateDir); err != nil {
		logger.Error("exiting", "err", err)
		os.Exit(1)
	}
}

// run holds the real program. Keeping main tiny means run can return errors
// (so deferred cleanup still happens) instead of calling os.Exit mid-way.
func run(ctx context.Context, logger *slog.Logger, hostname, stateDir string) error {
	// AuthKey is left empty on purpose: tsnet falls back to the TS_AUTHKEY
	// environment variable, and if that is also empty it logs a login URL.
	srv := &tsnet.Server{
		Hostname: hostname,
		Dir:      stateDir,
	}
	defer srv.Close()

	// Up blocks until the node is connected (or ctx is cancelled).
	status, err := srv.Up(ctx)
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	logger.Info("joined tailnet", "hostname", hostname, "ips", status.TailscaleIPs)

	// LocalClient talks to the embedded tailscaled inside this process.
	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	// Listen on the tailnet only. This port is not open on the host's
	// normal network interfaces.
	ln, err := srv.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	httpSrv := &http.Server{Handler: whoamiHandler(lc, logger)}

	// Serve blocks, so run it in a goroutine and wait for either a
	// serve error or a shutdown signal.
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()

	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down")
		// Proper graceful shutdown with a timeout comes in milestone 5.
		if err := httpSrv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// whoamiHandler returns an http.Handler that looks up who is calling.
// It is a function returning a closure so the handler can use lc and logger
// without global variables.
func whoamiHandler(lc *local.Client, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.RemoteAddr is "100.x.y.z:port" — the caller's tailnet address.
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if errors.Is(err, local.ErrPeerNotFound) {
			http.Error(w, "unknown caller", http.StatusForbidden)
			return
		}
		if err != nil {
			logger.Error("whois failed", "remote", r.RemoteAddr, "err", err)
			http.Error(w, "identity lookup failed", http.StatusInternalServerError)
			return
		}

		login := who.UserProfile.LoginName
		node := who.Node.ComputedName
		tags := who.Node.Tags // non-empty means a tagged node, not a person

		logger.Info("request", "login", login, "node", node, "tags", tags, "path", r.URL.Path)
		fmt.Fprintf(w, "login: %s\nnode:  %s\ntags:  %v\n", login, node, tags)
	})
}
