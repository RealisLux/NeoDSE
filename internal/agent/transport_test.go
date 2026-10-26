// File purpose: Verifies transport keepalives remain responsive during ordered hardware execution.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/gorilla/websocket"
)

// TestTransportDialerFailsClosedWhenWireGuardDisappears exercises the production dialer.
func TestTransportDialerFailsClosedWhenWireGuardDisappears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialer := newTransportDialer("neodse-missing")
	conn, err := dialer.NetDialContext(ctx, "tcp4", "192.0.2.1:80")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatalf("missing WireGuard must prevent network dialing: %v", err)
	}
}

// TestTransportReaderBoundsPendingWork floods an unconsumed real WebSocket
// queue and requires both small-frame and large-payload pressure to fail closed.
func TestTransportReaderBoundsPendingWork(t *testing.T) {
	for _, scenario := range []struct {
		name, payload, reason string
	}{
		{"frames", `{}`, "frame capacity"},
		{"bytes", `{"value":"` + strings.Repeat("x", 2<<20) + `"}`, "byte capacity"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upgrader := websocket.Upgrader{}
				ws, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer ws.Close()
				raw, err := json.Marshal(protocol.Frame{Type: "command", Payload: json.RawMessage(scenario.payload)})
				if err != nil {
					return
				}
				for index := 0; index <= transportInboundFrames; index++ {
					_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if err := ws.WriteJSON(raw); err != nil {
						return
					}
				}
			}))
			defer fixture.Close()
			dialer := newTransportDialer("")
			ws, _, err := dialer.Dial("ws"+strings.TrimPrefix(fixture.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			ws.SetReadLimit(4 << 20)
			_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
			frames := make(chan inboundFrame, transportInboundFrames)
			var queuedBytes atomic.Int64
			err = readTransportFrames(ws, frames, &queuedBytes)
			if err == nil || !strings.Contains(err.Error(), scenario.reason) {
				t.Fatalf("unbounded input returned %v", err)
			}
			if queuedBytes.Load() > transportInboundBytes || len(frames) > transportInboundFrames {
				t.Fatal("pending work exceeded its memory bounds")
			}
		})
	}
}

// TestTransportKeepaliveDuringHardwareCommand requires pongs while a hardware
// operation is blocked and verifies subsequent commands still execute in order.
func TestTransportKeepaliveDuringHardwareCommand(t *testing.T) {
	agent, _ := newSessionAgent(t)
	agent.clearSession()
	entered := make(chan instruction.DisplayOperation, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	agent.displayController = func(operation instruction.DisplayOperation) error {
		entered <- operation
		if operation == instruction.DisplayOn {
			<-release
		}
		return nil
	}
	pong := make(chan struct{})
	serverErrors := make(chan error, 1)
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer ws.Close()
		err = serveHardwareKeepaliveFixture(ws, agent, pong)
		if err != nil {
			serverErrors <- err
		}
	}))
	defer fixture.Close()
	agent.config.Transport.URL = "ws" + strings.TrimPrefix(fixture.URL, "http")
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- agent.runSession(ctx) }()
	defer func() {
		unblock()
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("transport session did not release its workers")
		}
	}()
	select {
	case operation := <-entered:
		if operation != instruction.DisplayOn {
			t.Fatalf("first command=%s", operation)
		}
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("hardware command did not start")
	}
	select {
	case <-pong:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("hardware operation blocked transport pong handling")
	}
	select {
	case operation := <-entered:
		t.Fatalf("subsequent command=%s ran before the first completed", operation)
	default:
	}
	unblock()
	select {
	case operation := <-entered:
		if operation != instruction.DisplayOff {
			t.Fatalf("second command=%s", operation)
		}
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("subsequent command was not executed")
	}
}

// serveHardwareKeepaliveFixture performs a real signed handshake and sends two
// ordered operations plus a ping whose reply must arrive before hardware resumes.
func serveHardwareKeepaliveFixture(ws *websocket.Conn, agent *Agent, pong chan<- struct{}) error {
	var raw []byte
	if err := ws.ReadJSON(&raw); err != nil {
		return err
	}
	var frame protocol.Frame
	var hello protocol.Hello
	if err := protocol.Decode(raw, &frame); err != nil {
		return err
	}
	if err := protocol.Decode(frame.Payload, &hello); err != nil {
		return err
	}
	handshake, err := agent.purposeKey(keyderivation.TransportHandshake)
	if err != nil {
		return err
	}
	welcome := protocol.Welcome{Protocol: protocol.Version, AgentID: agent.config.Agent.ID,
		ClientNonce: hello.ClientNonce, ServerNonce: strings.Repeat("22", 32),
		SessionID: strings.Repeat("33", 16), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	welcome.Signature, err = protocol.SignWelcome(welcome, handshake)
	if err != nil {
		return err
	}
	key, err := keyderivation.DeriveSession(agent.psk, agent.config.Agent.ID, welcome.ClientNonce, welcome.ServerNonce, keyderivation.TransportCommand)
	if err != nil {
		return err
	}
	values := []struct {
		kind  string
		value any
	}{{"welcome", welcome}}
	for index, operation := range []instruction.DisplayOperation{instruction.DisplayOn, instruction.DisplayOff} {
		now := time.Now().UTC()
		command := protocol.Command{Protocol: protocol.Version, AgentID: agent.config.Agent.ID,
			SessionID: welcome.SessionID, Sequence: uint64(index + 1), EventID: fmt.Sprintf("hardware-%d", index),
			Timestamp: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
			Command: instruction.NewCommand(instruction.DisplayCommand{Operation: operation})}
		command.Signature, err = protocol.SignCommand(command, key)
		if err != nil {
			return err
		}
		values = append(values, struct {
			kind  string
			value any
		}{"command", command})
	}
	for _, value := range values {
		payload, err := json.Marshal(value.value)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(protocol.Frame{Type: value.kind, Payload: payload})
		if err != nil {
			return err
		}
		if err := ws.WriteJSON(raw); err != nil {
			return err
		}
	}
	var once sync.Once
	ws.SetPongHandler(func(string) error { once.Do(func() { close(pong) }); return nil })
	if err := ws.WriteControl(websocket.PingMessage, []byte("hardware-running"), time.Now().Add(time.Second)); err != nil {
		return err
	}
	for {
		if err := ws.ReadJSON(&raw); err != nil {
			return nil
		}
	}
}

// TestExpiredCommandIsReportedWithoutResettingSession reports an authentic
// command that arrived too late instead of dropping the control session.
func TestExpiredCommandIsReportedWithoutResettingSession(t *testing.T) {
	agent, key := newSessionAgent(t)
	executed := false
	agent.displayController = func(instruction.DisplayOperation) error { executed = true; return nil }
	frames := make(chan protocol.Frame, 4)
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			var raw []byte
			var frame protocol.Frame
			if ws.ReadJSON(&raw) != nil || protocol.Decode(raw, &frame) != nil {
				return
			}
			frames <- frame
		}
	}))
	defer fixture.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(fixture.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	agent.connection = &agentConnection{ws: ws}

	now := time.Now().UTC()
	message := protocol.Command{
		Protocol: protocol.Version, SessionID: "session-1", Sequence: 1, EventID: "late",
		AgentID: agent.config.Agent.ID, Timestamp: now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		Command:   instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayMute}),
	}
	message.Signature, _ = protocol.SignCommand(message, key)
	if err := agent.handleCommand(message); err != nil {
		t.Fatalf("expired authentic command reset the session: %v", err)
	}
	if executed {
		t.Fatal("expired command was executed")
	}
	select {
	case frame := <-frames:
		var receipt protocol.Receipt
		if frame.Type != "receipt" || json.Unmarshal(frame.Payload, &receipt) != nil ||
			receipt.EventID != "late" || receipt.Status != "expired" || receipt.Operation != "display" {
			t.Fatalf("expired command frame=%s %s", frame.Type, frame.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expired command was not reported")
	}
	if agent.verifyCommand(message) != commandRejected {
		t.Fatal("replayed expired command was not rejected by the session sequence")
	}
}
