package internal

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TODO(template) update or delete this. See README.md.
func RunCmd() {
	// Listen for interrupt signals.
	interrupt := make(chan os.Signal, 1)
	// Ctrl-C
	signal.Notify(interrupt, os.Interrupt)
	// this is what docker sends when shutting down a container
	signal.Notify(interrupt, syscall.SIGTERM)

	// TODO(template) pass ctx to any long running goroutines started here so they can shutdown gracefully.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
			return

		case <-interrupt:
			log.Info().Msg("interrupt signal received - shutting down agent")
			cancel()
		}
	}()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	log.Info().Msg("Hello, world!")
}
