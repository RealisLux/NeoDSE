// File purpose: Verifies exact provisioning fields, encoding bounds, and malformed block rejection.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"
	"time"
)

const testWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// TestReadBlockCancellationInterruptsPipe verifies empty and partially pasted
// input cannot retain an interactive CLI after its signal context is canceled.
func TestReadBlockCancellationInterruptsPipe(t *testing.T) {
	for _, prefix := range []string{"", "NEODSE_PROVISIONING_VERSION=1\nAGENT_ID=partial"} {
		t.Run(fmt.Sprintf("bytes-%d", len(prefix)), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			if _, err := writer.WriteString(prefix); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				values, err := ReadBlock(ctx, reader)
				if values != nil {
					err = errors.New("canceled input returned provisioning values")
				}
				result <- err
			}()
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("canceled input error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt the pending input promptly")
			}
			if _, err := reader.Stat(); err != nil {
				t.Fatalf("cancellation closed the caller's input file: %v", err)
			}
		})
	}
}

// TestReadBlockReadsCompletePipe verifies a blank line completes input while
// the writer remains open, preserving the interactive provisioning contract.
func TestReadBlockReadsCompletePipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	request := AgentRequest{AgentID: "display-01", WireGuardPublicKey: testWGKey}
	if err := WriteAgentRequest(writer, request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	values, err := ReadBlock(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAgentRequest(values)
	if err != nil || parsed != request {
		t.Fatalf("pipe request=%#v error=%v", parsed, err)
	}
}

// TestProvisioningBlockBoundsAndSecretErrors rejects resource abuse without echoing pasted secrets.
func TestProvisioningBlockBoundsAndSecretErrors(t *testing.T) {
	const secret = "sensitive-pasted-credential"
	for _, input := range []string{
		"NEODSE_PROVISIONING_VERSION=1\n" + secret + "\n\n",
		"NEODSE_PROVISIONING_VERSION=" + secret + "\n\n",
		"NEODSE_PROVISIONING_VERSION=1\n" + secret + "=a\n" + secret + "=b\n\n",
	} {
		_, err := parseBlock(strings.NewReader(input))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("expected a redacted parsing error, got %v", err)
		}
	}
	if err := exactFields(map[string]string{secret: "value"}, "AGENT_ID"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("expected a redacted unknown-field error, got %v", err)
	}
	var block strings.Builder
	block.WriteString("NEODSE_PROVISIONING_VERSION=1\n")
	for index := range maxBlockFields {
		fmt.Fprintf(&block, "FIELD_%d=value\n", index)
	}
	if _, err := parseBlock(strings.NewReader(block.String())); err == nil {
		t.Fatal("accepted more fields than the largest supported block")
	}
	if _, err := parseBlock(strings.NewReader("NEODSE_PROVISIONING_VERSION=1\nVALUE=" + strings.Repeat("x", maxBlockLineBytes))); err == nil {
		t.Fatal("accepted an oversized field")
	}
}

// TestAgentRequestRoundTrip verifies agent request round trip.
func TestAgentRequestRoundTrip(t *testing.T) {
	want := AgentRequest{AgentID: "display-01", WireGuardPublicKey: testWGKey}
	var output bytes.Buffer
	if err := WriteAgentRequest(&output, want); err != nil {
		t.Fatal(err)
	}
	values, err := parseBlock(strings.NewReader(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAgentRequest(values)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("request = %+v, want %+v", got, want)
	}
}

// TestProvisioningBlockRejectsUnknownAndDuplicateFields verifies provisioning block rejects unknown and duplicate fields.
func TestProvisioningBlockRejectsUnknownAndDuplicateFields(t *testing.T) {
	for _, block := range []string{
		"NEODSE_PROVISIONING_VERSION=1\nAGENT_ID=a\nAGENT_ID=b\nWG_PUBLIC_KEY=" + testWGKey + "\n\n",
		"NEODSE_PROVISIONING_VERSION=1\nAGENT_ID=a\nWG_PUBLIC_KEY=" + testWGKey + "\nEXTRA=value\n\n",
	} {
		values, err := parseBlock(strings.NewReader(block))
		if err == nil {
			_, err = ParseAgentRequest(values)
		}
		if err == nil {
			t.Fatalf("invalid block accepted: %q", block)
		}
	}
}

// FuzzProvisioningBlock exercises provisioning block with generated inputs.
func FuzzProvisioningBlock(f *testing.F) {
	f.Add("NEODSE_PROVISIONING_VERSION=1\nAGENT_ID=display-01\nWG_PUBLIC_KEY=" + testWGKey + "\n\n")
	f.Add("NEODSE_PROVISIONING_VERSION=1\nAGENT_ID=a\nAGENT_ID=b\n\n")
	f.Add("\x00\xff\n")
	f.Fuzz(func(t *testing.T, input string) {
		values, err := parseBlock(strings.NewReader(input))
		if err != nil {
			return
		}
		_, _ = ParseAgentRequest(values)
		_, _ = ParseServerResponse(values)
	})
}

// TestServerResponseValidation verifies server response validation.
func TestServerResponseValidation(t *testing.T) {
	want := ServerResponse{ServerPublicKey: testWGKey, PresharedKey: testWGKey, ServerEndpoint: "vpn.example:51820", ServerAddress: "10.99.0.1", TransportURL: "ws://10.99.0.1:8081", ProxyURL: "http://10.99.0.1:3128", AgentAddress: "10.99.0.2", AgentPSK: strings.Repeat("ab", 32)}
	var output bytes.Buffer
	if err := WriteServerResponse(&output, want); err != nil {
		t.Fatal(err)
	}
	values, err := parseBlock(strings.NewReader(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseServerResponse(values)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("response = %+v, want %+v", got, want)
	}
}

// TestAgentRequestValidationMatrix verifies agent request validation matrix.
func TestAgentRequestValidationMatrix(t *testing.T) {
	tests := []map[string]string{
		{"NEODSE_PROVISIONING_VERSION": Version, "AGENT_ID": "../agent", "WG_PUBLIC_KEY": testWGKey},
		{"NEODSE_PROVISIONING_VERSION": Version, "AGENT_ID": "display-01", "WG_PUBLIC_KEY": "invalid"},
		{"NEODSE_PROVISIONING_VERSION": Version, "AGENT_ID": "display-01"},
	}
	for _, values := range tests {
		if _, err := ParseAgentRequest(values); err == nil {
			t.Fatalf("invalid agent request accepted: %#v", values)
		}
	}
}

// TestServerResponseRejectsInvalidFields verifies server response rejects invalid fields.
func TestServerResponseRejectsInvalidFields(t *testing.T) {
	valid := map[string]string{
		"NEODSE_PROVISIONING_VERSION": Version,
		"SERVER_PUBLIC_KEY":           testWGKey,
		"PRESHARED_KEY":               testWGKey,
		"SERVER_ENDPOINT":             "vpn.example:51820",
		"SERVER_ADDRESS":              "10.99.0.1",
		"TRANSPORT_URL":               "ws://10.99.0.1:8081",
		"PROXY_URL":                   "http://10.99.0.1:3128",
		"AGENT_ADDRESS":               "10.99.0.2",
		"AGENT_PSK":                   strings.Repeat("ab", 32),
	}
	tests := map[string]func(map[string]string){
		"newline key":             func(v map[string]string) { v["SERVER_PUBLIC_KEY"] = testWGKey + "\n" },
		"newline endpoint":        func(v map[string]string) { v["SERVER_ENDPOINT"] = "vpn.example\nPostUp=bad:51820" },
		"empty endpoint host":     func(v map[string]string) { v["SERVER_ENDPOINT"] = ":51820" },
		"same addresses":          func(v map[string]string) { v["AGENT_ADDRESS"] = "10.99.0.1" },
		"public agent":            func(v map[string]string) { v["AGENT_ADDRESS"] = "192.0.2.1" },
		"transport peer mismatch": func(v map[string]string) { v["TRANSPORT_URL"] = "ws://10.99.0.9:8081" },
		"proxy peer mismatch":     func(v map[string]string) { v["PROXY_URL"] = "http://10.99.0.9:3128" },
		"key":                     func(v map[string]string) { v["SERVER_PUBLIC_KEY"] = "invalid" },
		"endpoint":                func(v map[string]string) { v["SERVER_ENDPOINT"] = "missing-port" },
		"IPv6 endpoint":           func(v map[string]string) { v["SERVER_ENDPOINT"] = "[2001:db8::1]:51820" },
		"mapped endpoint":         func(v map[string]string) { v["SERVER_ENDPOINT"] = "[::ffff:192.0.2.1]:51820" },
		"server address":          func(v map[string]string) { v["SERVER_ADDRESS"] = "2001:db8::1" },
		"agent address":           func(v map[string]string) { v["AGENT_ADDRESS"] = "invalid" },
		"transport scheme":        func(v map[string]string) { v["TRANSPORT_URL"] = "wss://10.99.0.1:8081" },
		"transport user":          func(v map[string]string) { v["TRANSPORT_URL"] = "ws://user@10.99.0.1:8081" },
		"IPv6 transport":          func(v map[string]string) { v["TRANSPORT_URL"] = "ws://[fd00::1]:8081" },
		"proxy scheme":            func(v map[string]string) { v["PROXY_URL"] = "https://10.99.0.1:3128" },
		"IPv6 proxy":              func(v map[string]string) { v["PROXY_URL"] = "http://[fd00::1]:3128" },
		"proxy query":             func(v map[string]string) { v["PROXY_URL"] = "http://10.99.0.1:3128?x=1" },
		"PSK length":              func(v map[string]string) { v["AGENT_PSK"] = "ab" },
		"PSK encoding":            func(v map[string]string) { v["AGENT_PSK"] = strings.Repeat("gg", 32) },
		"unknown field":           func(v map[string]string) { v["EXTRA"] = "value" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(valid)+1)
			maps.Copy(values, valid)
			mutate(values)
			if _, err := ParseServerResponse(values); err == nil {
				t.Fatal("invalid server response was accepted")
			}
		})
	}
}

// TestReadBlockRejectsSyntaxVersionAndOversizedLine verifies read block rejects syntax version and oversized line.
func TestReadBlockRejectsSyntaxVersionAndOversizedLine(t *testing.T) {
	for _, block := range []string{
		"NEODSE_PROVISIONING_VERSION=2\n\n",
		"NEODSE_PROVISIONING_VERSION=1\ninvalid\n\n",
		"NEODSE_PROVISIONING_VERSION=1\nEMPTY=\n\n",
		"NEODSE_PROVISIONING_VERSION=1\nVALUE=" + strings.Repeat("a", 70<<10) + "\n\n",
	} {
		if _, err := parseBlock(strings.NewReader(block)); err == nil {
			t.Fatal("invalid provisioning block was accepted")
		}
	}
}
