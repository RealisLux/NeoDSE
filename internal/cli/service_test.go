// File purpose: Verifies service argument handling, help and failure results, and signal cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"
)

// TestRunServiceAnswersVersionWithoutStarting keeps --version free of service side effects.
func TestRunServiceAnswersVersionWithoutStarting(t *testing.T) {
	var output bytes.Buffer
	err := runService(t.Context(), "neodse-proxy", "1.2.3", []string{"--version"}, &output, func(context.Context, []string, string) error {
		t.Fatal("service started for --version")
		return nil
	})
	if err != nil || output.String() != "neodse-proxy 1.2.3\n" {
		t.Fatalf("err = %v, output = %q", err, output.String())
	}
}

// TestRunServicePassesArgumentsAndReportsFailures treats --help as success and returns other errors.
func TestRunServicePassesArgumentsAndReportsFailures(t *testing.T) {
	failure := errors.New("listen failed")
	for _, test := range []struct {
		result error
		want   error
	}{{nil, nil}, {flag.ErrHelp, nil}, {fmt.Errorf("parse flags: %w", flag.ErrHelp), nil}, {failure, failure}} {
		var gotArgs []string
		var gotVersion string
		err := runService(t.Context(), "neodse-agent", "dev", []string{"--config", "/etc/neodse/agent.yaml"}, &bytes.Buffer{}, func(_ context.Context, args []string, version string) error {
			gotArgs, gotVersion = args, version
			return test.result
		})
		if !errors.Is(err, test.want) || (test.want == nil && err != nil) {
			t.Errorf("service result %v: err = %v, want %v", test.result, err, test.want)
		}
		if !slices.Equal(gotArgs, []string{"--config", "/etc/neodse/agent.yaml"}) || gotVersion != "dev" {
			t.Errorf("service received args %q version %q", gotArgs, gotVersion)
		}
	}
}

// TestRunServiceCancelsOnTermination stops the service context on SIGTERM instead of killing the process.
func TestRunServiceCancelsOnTermination(t *testing.T) {
	err := runService(t.Context(), "neodse-transport", "dev", nil, &bytes.Buffer{}, func(ctx context.Context, _ []string, _ string) error {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("SIGTERM did not cancel the service context")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}
