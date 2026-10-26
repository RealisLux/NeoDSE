// File purpose: Verifies release-test reporting rejects skipped prerequisites and truncated evidence.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRequiredTestResults rejects false-success evidence while allowing explicitly separate integration gates.
func TestRequiredTestResults(t *testing.T) {
	const start = "{\"Package\":\"fixture\",\"Action\":\"start\"}\n"
	const pass = "{\"Package\":\"fixture\",\"Action\":\"pass\"}\n"
	const skip = "{\"Package\":\"fixture\",\"Test\":\"Integration\",\"Action\":\"skip\"}\n"
	const testPass = "{\"Package\":\"fixture\",\"Test\":\"PackageMetadata\",\"Action\":\"pass\"}\n"
	for _, scenario := range []struct {
		name, events string
		args         []string
		wantSuccess  bool
	}{
		{"pass", start + pass, nil, true},
		{"unexpected skip", start + skip + pass, nil, false},
		{"deferred integration", start + skip + pass, []string{"--allow-skip", "fixture:Integration"}, true},
		{"other skip", start + skip + pass, []string{"--allow-skip", "fixture:Other"}, false},
		{"required test passed", start + testPass + pass, []string{"--require-test", "fixture:PackageMetadata"}, true},
		{"renamed test", start + testPass + pass, []string{"--require-test", "fixture:ObsoleteName"}, false},
		{"no matching test", start + pass, []string{"--require-test", "fixture:PackageMetadata"}, false},
		{"required test in another package", start + testPass + pass, []string{"--require-test", "other:PackageMetadata"}, false},
		{"required test skipped", start + skip + pass, []string{"--allow-skip", "fixture:Integration", "--require-test", "fixture:Integration"}, false},
		{"malformed required test", start + testPass + pass, []string{"--require-test", "PackageMetadata"}, false},
		{"failure", start + "{\"Package\":\"fixture\",\"Action\":\"fail\"}\n", nil, false},
		{"truncated", start, nil, false},
		{"empty", "", nil, false},
		{"invalid json", start + "not json\n" + pass, nil, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			args := append([]string{filepath.Join(repositoryRoot(t), "scripts", "check-test-results.py")}, scenario.args...)
			command := exec.Command("python3", args...)
			command.Stdin = strings.NewReader(scenario.events)
			output, err := command.CombinedOutput()
			if (err == nil) != scenario.wantSuccess {
				t.Fatalf("success=%t want=%t: %s", err == nil, scenario.wantSuccess, output)
			}
		})
	}
}

// TestTestResultDiagnostics keeps the original reason for CI failures visible without noisy passing logs.
func TestTestResultDiagnostics(t *testing.T) {
	event := func(fields map[string]string) string {
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded) + "\n"
	}
	output := func(test, text string) string {
		fields := map[string]string{"Package": "fixture", "Action": "output", "Output": text}
		if test != "" {
			fields["Test"] = test
		}
		return event(fields)
	}
	const start = "{\"Package\":\"fixture\",\"Action\":\"start\"}\n"
	const pass = "{\"Package\":\"fixture\",\"Action\":\"pass\"}\n"
	const fail = "{\"Package\":\"fixture\",\"Action\":\"fail\"}\n"
	const testFail = "{\"Package\":\"fixture\",\"Test\":\"TestFleet\",\"Action\":\"fail\"}\n"
	const skip = "{\"Package\":\"fixture\",\"Test\":\"Integration\",\"Action\":\"skip\"}\n"
	for _, scenario := range []struct {
		name, events string
		args         []string
		wantSuccess  bool
		want, absent []string
		maxOutput    int
	}{
		{
			name:   "assertion and repeated failure summaries",
			events: start + output("TestFleet", "fleet_test.go:42: expected 128 clients, got 127\n") + testFail + fail,
			want:   []string{"fleet_test.go:42: expected 128 clients, got 127\n", "FAIL fixture/TestFleet\n", "\nFAIL fixture\n"},
		},
		{
			name:   "package race without test attribute",
			events: start + output("", "WARNING: DATA RACE\nRead at 0x123 by goroutine 12:\nserver/app.go:42\n") + fail,
			want:   []string{"WARNING: DATA RACE\nRead at 0x123 by goroutine 12:\nserver/app.go:42\n"},
		},
		{
			name: "panic in unfinished test",
			events: start + output("TestFleet", "panic: test timed out after 15m0s\n") +
				output("", "goroutine 12 [running]:\nserver.app()\n") + fail,
			want: []string{"panic: test timed out after 15m0s\n", "goroutine 12 [running]:\nserver.app()\n"},
		},
		{
			name: "diagnostics after first failure",
			events: start + output("TestFleet", "fleet_test.go:42: failed connection\n") + testFail +
				output("", "cleanup.go:18: failed cleanup\n") + fail,
			want: []string{"fleet_test.go:42: failed connection\n", "cleanup.go:18: failed cleanup\n"},
		},
		{
			name: "child and parent diagnostics appear once",
			events: start + output("TestFleet/Connect", "fleet_test.go:42: child failed\n") +
				"{\"Package\":\"fixture\",\"Test\":\"TestFleet/Connect\",\"Action\":\"fail\"}\n" +
				output("TestFleet", "fleet_test.go:45: parent cleanup failed\n") + testFail + fail,
			want: []string{"fleet_test.go:42: child failed\n", "fleet_test.go:45: parent cleanup failed\n", "\nFAIL fixture\n"},
		},
		{
			name:        "quiet passing package",
			events:      start + output("TestFleet", "verbose successful test log\n") + pass,
			wantSuccess: true,
			want:        []string{"PASS fixture\n"},
			absent:      []string{"verbose successful test log", "Go test output"},
		},
		{
			name: "interleaved successful package stays quiet",
			events: start + "{\"Package\":\"other\",\"Action\":\"start\"}\n" +
				event(map[string]string{"Package": "other", "Action": "output", "Output": "unrelated passing log\n"}) +
				output("TestFleet", "fleet_test.go:42: connection failed\n") + testFail +
				"{\"Package\":\"other\",\"Action\":\"pass\"}\n" + fail,
			want:   []string{"fleet_test.go:42: connection failed\n", "PASS other\n"},
			absent: []string{"unrelated passing log"},
		},
		{
			name:   "truncated stream retains panic",
			events: start + output("TestFleet", "panic: unexpected EOF\n"),
			want:   []string{"panic: unexpected EOF\n", "Incomplete Go test result stream"},
		},
		{
			name:   "invalid stream retains preceding context",
			events: start + output("TestFleet", "fleet_test.go:42: context before invalid event\n") + "not json\n",
			want:   []string{"fleet_test.go:42: context before invalid event\n", "not json\n", "Invalid test result stream"},
		},
		{
			name:   "missing start retains original output",
			events: output("", "panic before start\n") + pass,
			want:   []string{"panic before start\n", "Incomplete Go test result stream"},
		},
		{
			name:   "missing required test retains package explanation",
			events: start + output("", "testing: warning: no tests to run\n") + pass,
			args:   []string{"--require-test", "fixture:TestFleet"},
			want:   []string{"testing: warning: no tests to run\n", "Required Go tests did not pass"},
		},
		{
			name:   "unexpected skip retains reason",
			events: start + output("Integration", "suite_test.go:12: missing prerequisite\n") + skip + pass,
			want:   []string{"suite_test.go:12: missing prerequisite\n", "UNEXPECTED SKIP fixture/Integration"},
		},
		{
			name:        "allowed skip stays quiet",
			events:      start + output("Integration", "suite_test.go:12: deferred integration\n") + skip + pass,
			args:        []string{"--allow-skip", "fixture:Integration"},
			wantSuccess: true,
			want:        []string{"DEFERRED SKIP fixture/Integration"},
			absent:      []string{"suite_test.go:12: deferred integration"},
		},
		{
			name:   "required allowed skip retains reason",
			events: start + output("Integration", "suite_test.go:12: required integration missing\n") + skip + pass,
			args:   []string{"--allow-skip", "fixture:Integration", "--require-test", "fixture:Integration"},
			want:   []string{"suite_test.go:12: required integration missing\n", "Required Go tests did not pass"},
		},
		{
			name: "compiler diagnostics",
			events: event(map[string]string{"ImportPath": "fixture [fixture.test]", "Action": "build-output", "Output": "fixture.go:42: undefined: obsoleteFeature\n"}) +
				event(map[string]string{"ImportPath": "fixture [fixture.test]", "Action": "build-fail"}) + start + fail,
			want:   []string{"fixture.go:42: undefined: obsoleteFeature\n", "FAIL fixture [fixture.test] (build)\n"},
			absent: []string{"Invalid test result stream"},
		},
		{
			name: "large logs retain startup and failure with truncation notice",
			events: start + output("TestFleet", "startup configuration\n"+strings.Repeat("verbose test log\n", 16*1024)+
				"fleet_test.go:42: failed after noisy logs\n") + testFail + fail,
			want:      []string{"startup configuration\n", "output characters omitted", "fleet_test.go:42: failed after noisy logs\n"},
			maxOutput: 130 * 1024,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			args := append([]string{filepath.Join(repositoryRoot(t), "scripts", "check-test-results.py")}, scenario.args...)
			command := exec.Command("python3", args...)
			command.Stdin = strings.NewReader(scenario.events)
			output, err := command.CombinedOutput()
			if (err == nil) != scenario.wantSuccess {
				t.Fatalf("success=%t want=%t: %s", err == nil, scenario.wantSuccess, output)
			}
			for _, want := range scenario.want {
				if count := strings.Count(string(output), want); count != 1 {
					t.Errorf("diagnostic %q appeared %d times, want once: %s", want, count, output)
				}
			}
			for _, absent := range scenario.absent {
				if strings.Contains(string(output), absent) {
					t.Errorf("unexpected diagnostic %q: %s", absent, output)
				}
			}
			if scenario.maxOutput > 0 && len(output) > scenario.maxOutput {
				t.Errorf("diagnostics exceed output limit: got %d bytes, maximum %d", len(output), scenario.maxOutput)
			}
		})
	}
}
