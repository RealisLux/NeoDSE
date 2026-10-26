// File purpose: Verifies rejected connections release workers and isolate bounded resource pressure.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/gorilla/websocket"
)

// TestRejectedIdentityChurnPreservesController checks historical identities cannot exhaust live capacity.
func TestRejectedIdentityChurnPreservesController(t *testing.T) {
	previousLog := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(previousLog)
	completed := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	transport := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			completed <- err
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(20 * time.Second))
		for index := range controllerMaxAgentWorkers + 1 {
			id, connectionID := fmt.Sprintf("unprovisioned-%d", index), fmt.Sprintf("%032x", index+1)
			for _, frame := range []routedFrame{
				{Type: "connected", AgentID: id, ConnectionID: connectionID},
				{Type: "from_agent", AgentID: id, ConnectionID: connectionID, Payload: []byte("{}")},
			} {
				if err := connection.WriteJSON(frame); err != nil {
					completed <- fmt.Errorf("identity %d: %w", index, err)
					return
				}
			}
			var response routedFrame
			if err := connection.ReadJSON(&response); err != nil {
				completed <- fmt.Errorf("identity %d: %w", index, err)
				return
			}
			if response.Type != "disconnect" || response.AgentID != id {
				completed <- fmt.Errorf("wrong rejection for identity %d: %+v", index, response)
				return
			}
			if err := connection.WriteJSON(routedFrame{Type: "disconnected", AgentID: id, ConnectionID: connectionID}); err != nil {
				completed <- err
				return
			}
		}
		completed <- nil
	}))
	defer transport.Close()
	controller := newServer(Config{}, "test")
	link := newControllerLink(controller, "ws"+strings.TrimPrefix(transport.URL, "http"), strings.Repeat("ab", 32))
	controller.link = link
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = link.session(ctx)
	if err := <-completed; err != nil {
		t.Fatalf("controller did not survive sequential rejected identities: %v", err)
	}
}

// controllerWorkerFrame creates a fresh valid hello for a connection lifecycle test.
func controllerWorkerFrame(t *testing.T, connectionID string) routedFrame {
	t.Helper()
	psk, err := keyderivation.ParsePSK(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyderivation.Derive(psk, "display", keyderivation.TransportHandshake)
	if err != nil {
		t.Fatal(err)
	}
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: "display", Version: "test",
		ClientNonce: strings.Repeat(connectionID, 2), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, err = protocol.SignHello(hello, key)
	if err != nil {
		t.Fatal(err)
	}
	return routedFrame{Type: "from_agent", AgentID: "display", ConnectionID: connectionID,
		Payload: mustJSON(t, protocol.Frame{Type: "hello", Payload: mustJSON(t, hello)})}
}

// blockedControllerWorkers holds a real hello handler in flight until test cleanup.
func blockedControllerWorkers(t *testing.T) *agentFrameWorkers {
	t.Helper()
	controller := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	controller.agentConnected("display")
	oldID := fmt.Sprintf("%032x", 1)
	link := &controllerLink{s: controller, conn: &websocket.Conn{}, routes: map[string]string{"display": oldID}}
	controller.link = link
	entered, release := make(chan struct{}, 2), make(chan struct{})
	controller.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type == "welcome" {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	var group sync.WaitGroup
	var budget atomic.Int64
	workers := newAgentFrameWorkers(ctx, link, &group, &budget)
	t.Cleanup(func() {
		cancel()
		workers.stop()
		link.mu.Lock()
		link.conn = nil
		link.mu.Unlock()
		close(release)
		group.Wait()
		workers.reap()
		if workers.workerCount != 0 || budget.Load() != 0 {
			t.Errorf("shutdown retained workers=%d bytes=%d", workers.workerCount, budget.Load())
		}
	})
	if err := workers.enqueue(controllerWorkerFrame(t, oldID)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("hello did not enter the blocked welcome write")
	}
	return workers
}

// TestControllerWorkerRetirementPreservesReplacement verifies draining does not release its live slot early.
func TestControllerWorkerRetirementPreservesReplacement(t *testing.T) {
	workers := blockedControllerWorkers(t)
	inFlight := workers.budget.Load()
	oldID, newID := fmt.Sprintf("%032x", 1), fmt.Sprintf("%032x", 2)
	frame := controllerWorkerFrame(t, oldID)
	if err := workers.enqueue(frame); err != nil {
		t.Fatal(err)
	}
	workers.link.mu.Lock()
	workers.link.routes["display"] = newID
	workers.link.mu.Unlock()
	workers.lifecycle(routedFrame{Type: "connected", AgentID: "display", ConnectionID: newID})
	if workers.budget.Load() != inFlight || workers.workerCount != 1 {
		t.Fatal("retirement must free queued bytes while retaining the in-flight reservation and worker slot")
	}
	if err := workers.enqueue(controllerWorkerFrame(t, newID)); err != nil {
		t.Fatal(err)
	}
	current := workers.active["display"]
	workers.lifecycle(routedFrame{Type: "disconnected", AgentID: "display", ConnectionID: oldID})
	if workers.active["display"] != current || workers.workerCount != 2 {
		t.Fatal("stale disconnect retired the replacement or lost predecessor accounting")
	}
	select {
	case <-current.done:
		t.Fatal("replacement processed before its predecessor finished")
	case <-time.After(25 * time.Millisecond):
	}
	if len(current.queue) != 1 {
		t.Fatal("replacement consumed work while the previous handler was in flight")
	}
}

// TestControllerInboundBudgetIncludesInFlight prevents slow handlers from
// releasing capacity while they still retain an unauthenticated payload.
func TestControllerInboundBudgetIncludesInFlight(t *testing.T) {
	workers := blockedControllerWorkers(t)
	if workers.budget.Load() <= 0 {
		t.Fatal("blocked hello handler released its inbound byte reservation")
	}
}

// TestControllerInboundReservationsReleaseOnExit covers consumed, stale, and
// cancelled work without leaving payload reservations behind.
func TestControllerInboundReservationsReleaseOnExit(t *testing.T) {
	for _, scenario := range []string{"processed", "stale route", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			controller := newServer(Config{}, "test")
			connectionID := strings.Repeat("ab", 16)
			link := &controllerLink{s: controller, conn: &websocket.Conn{}, routes: map[string]string{"display": connectionID}}
			if scenario == "stale route" {
				link.routes["display"] = strings.Repeat("cd", 16)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			queue := make(chan routedFrame, 2)
			var budget atomic.Int64
			for range cap(queue) {
				frame := routedFrame{AgentID: "display", ConnectionID: connectionID, Payload: []byte(`{}`)}
				budget.Add(int64(len(frame.Payload)))
				queue <- frame
			}
			close(queue)
			link.processAgentFrames(ctx, queue, &budget)
			if got := budget.Load(); got != 0 {
				t.Fatalf("handler exit retained %d inbound bytes", got)
			}
		})
	}
}

// TestControllerWorkerCapacityIncludesDraining bounds reconnects behind a blocked handler.
func TestControllerWorkerCapacityIncludesDraining(t *testing.T) {
	workers := blockedControllerWorkers(t)
	for index := 2; index <= controllerMaxAgentWorkers; index++ {
		connectionID := fmt.Sprintf("%032x", index)
		workers.lifecycle(routedFrame{Type: "connected", AgentID: "display", ConnectionID: connectionID})
		if err := workers.enqueue(controllerWorkerFrame(t, connectionID)); err != nil {
			t.Fatalf("worker %d: %v", index, err)
		}
	}
	if err := workers.enqueue(routedFrame{AgentID: "another", ConnectionID: strings.Repeat("cd", 16)}); err == nil {
		t.Fatal("draining workers did not consume the global worker bound")
	}
	if workers.workerCount != controllerMaxAgentWorkers {
		t.Fatalf("worker bound changed: %d", workers.workerCount)
	}
}

// TestControllerQueueLimitsReleaseBytes checks both memory and frame bounds without waiting on handlers.
func TestControllerQueueLimitsReleaseBytes(t *testing.T) {
	for _, scenario := range []struct {
		name, reason string
		size         int
	}{{"frames", "agent queue capacity", 1}, {"bytes", "controller inbound byte capacity", 2 << 20}} {
		t.Run(scenario.name, func(t *testing.T) {
			workers := blockedControllerWorkers(t)
			inFlight := workers.budget.Load()
			connectionID := fmt.Sprintf("%032x", 1)
			frame := routedFrame{AgentID: "display", ConnectionID: connectionID, Payload: make([]byte, scenario.size)}
			queued := 32
			if scenario.size > 1 {
				queued = int(((64 << 20) - inFlight) / int64(scenario.size))
			}
			for range queued {
				if err := workers.enqueue(frame); err != nil {
					t.Fatal(err)
				}
			}
			reserved := workers.budget.Load()
			if err := workers.enqueue(frame); err == nil || !strings.Contains(err.Error(), scenario.reason) {
				t.Fatalf("queue bound error = %v", err)
			}
			if workers.budget.Load() != reserved {
				t.Fatal("rejected frame retained a byte reservation")
			}
			workers.retire("display", connectionID)
			if workers.budget.Load() != inFlight {
				t.Fatal("retirement must release queued bytes and retain the blocked handler's reservation")
			}
		})
	}
}
