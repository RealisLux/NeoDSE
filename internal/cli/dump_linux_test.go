// File purpose: Verifies process dump protection before service or maintenance work starts.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestServiceDisablesProcessDumping checks kernel state in an isolated process;
// neither the irreversible core limit nor dumpability changes affect this test runner.
func TestServiceDisablesProcessDumping(t *testing.T) {
	const childEnvironment = "NEODSE_TEST_PROCESS_DUMPING"
	if os.Getenv(childEnvironment) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestServiceDisablesProcessDumping$")
		command.Env = append(os.Environ(), childEnvironment+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("process dump protection: %v\n%s", err, output)
		}
		return
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	called := false
	err := runService(t.Context(), "neodse-server", "test", []string{"unlock"}, &bytes.Buffer{}, func(context.Context, []string, string) error {
		called = true
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dumpable != 0 {
			return fmt.Errorf("process remains dumpable: value=%d error=%v", dumpable, err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			return err
		}
		if limit.Cur != 0 || limit.Max != 0 {
			return fmt.Errorf("core dump limit remains enabled: %+v", limit)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("protected maintenance callback: called=%v error=%v", called, err)
	}
}
