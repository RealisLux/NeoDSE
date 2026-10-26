// File purpose: Runs one NeoDSE service process with redacting logs and signal cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/RealisLux/NeoDSE/internal/logging"
)

// Service runs one NeoDSE service with its command-line arguments and build version until ctx is cancelled.
type Service func(ctx context.Context, args []string, version string) error

// Main configures the redacting logger and runs serve until SIGINT or SIGTERM.
// A failure is logged and exits with status 1.
func Main(name, version string, serve Service) {
	logging.Configure()
	if err := runService(context.Background(), name, version, os.Args[1:], os.Stdout, serve); err != nil {
		log.Fatal(err)
	}
}

// runService answers --version without side effects, otherwise runs serve
// until SIGINT or SIGTERM. A --help request is not a failure.
func runService(ctx context.Context, name, version string, args []string, output io.Writer, serve Service) error {
	if WriteVersion(output, name, version, args) {
		return nil
	}
	if err := DisableProcessDumping(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, args, version); err != nil && !errors.Is(err, flag.ErrHelp) {
		return err
	}
	return nil
}
