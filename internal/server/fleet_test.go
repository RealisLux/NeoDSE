// File purpose: Exercises a hundred authenticated simulated displays over real service connections.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/transport"
	"github.com/gorilla/websocket"
)

type fleetDisplay struct {
	id, endpoint string
	mu           sync.Mutex
	conn         *websocket.Conn
	credential   string
	started      time.Time
	slow         bool
	applied      atomic.Uint64
	generation   string
	revision     uint64
	seen         map[string]struct{}
	recent       []string
	failures     chan error
	jpeg         []byte
}

// fleetWriter serializes the heartbeat and command replies into one sequence.
type fleetWriter struct {
	mu       sync.Mutex
	conn     *websocket.Conn
	keys     map[keyderivation.Purpose][]byte
	sequence uint64
}

// send signs and serializes one fixture message with the next shared sequence.
func (w *fleetWriter) send(value any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sequence++
	switch message := value.(type) {
	case protocol.Status:
		message.Sequence = w.sequence
		message.Signature, _ = protocol.SignStatus(message, w.keys[keyderivation.TransportStatus])
		return fleetSend(w.conn, "status", message)
	case protocol.Display:
		message.Sequence = w.sequence
		message.Signature, _ = protocol.SignDisplay(message, w.keys[keyderivation.TransportDisplay])
		return fleetSend(w.conn, "display", message)
	case protocol.Receipt:
		message.Sequence = w.sequence
		message.Signature, _ = protocol.SignReceipt(message, w.keys[keyderivation.TransportReceipt])
		return fleetSend(w.conn, "receipt", message)
	default:
		return errors.New("protocol: unsupported simulated reply")
	}
}

// disconnect interrupts a simulated peer without racing its single reader/writer.
func (d *fleetDisplay) disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		_ = d.conn.Close()
	}
}

// run reconnects a simulated display while keeping hardware observations outside its volatile session.
func (d *fleetDisplay) run(ctx context.Context) {
	for ctx.Err() == nil {
		err := d.session(ctx)
		if err != nil && strings.HasPrefix(err.Error(), "protocol:") {
			select {
			case d.failures <- fmt.Errorf("%s: %w", d.id, err):
			default:
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// fleetSend uses the exact nested envelope expected by the production transport.
func fleetSend(conn *websocket.Conn, kind string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	frame, err := json.Marshal(protocol.Frame{Type: kind, Payload: payload})
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return conn.WriteJSON(frame)
}

// fleetRead decodes a bounded application frame from the transport's opaque payload.
func fleetRead(conn *websocket.Conn) (protocol.Frame, error) {
	var payload []byte
	if err := conn.ReadJSON(&payload); err != nil {
		return protocol.Frame{}, err
	}
	var frame protocol.Frame
	err := protocol.Decode(payload, &frame)
	return frame, err
}

// session authenticates both endpoints and acknowledges only verified, ordered operations.
func (d *fleetDisplay) session(ctx context.Context) error {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, d.endpoint+"/v1/agents/"+d.id, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(4 << 20)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	d.mu.Lock()
	d.conn = conn
	credential := d.credential
	d.mu.Unlock()
	psk, _ := keyderivation.ParsePSK(credential)
	handshake, _ := keyderivation.Derive(psk, d.id, keyderivation.TransportHandshake)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	hello := protocol.Hello{Protocol: protocol.Version, AgentID: d.id, Version: "integration-simulator", ClientNonce: hex.EncodeToString(nonce), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	hello.Signature, _ = protocol.SignHello(hello, handshake)
	if err := fleetSend(conn, "hello", hello); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := fleetRead(conn)
	if err != nil {
		return err
	}
	var welcome protocol.Welcome
	if frame.Type != "welcome" || protocol.Decode(frame.Payload, &welcome) != nil {
		return errors.New("protocol: expected welcome")
	}
	expected, _ := protocol.SignWelcome(welcome, handshake)
	if !protocol.Verify(welcome.Signature, expected) || welcome.ClientNonce != hello.ClientNonce || welcome.AgentID != d.id {
		return errors.New("protocol: invalid welcome")
	}
	keys, err := keyderivation.DeriveSessionKeys(psk, d.id, hello.ClientNonce, welcome.ServerNonce)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	if d.slow {
		<-ctx.Done()
		return ctx.Err()
	}
	writer := &fleetWriter{conn: conn, keys: keys}
	sendStatus := func() error {
		now := time.Now().UTC()
		return writer.send(protocol.Status{Protocol: protocol.Version, SessionID: welcome.SessionID,
			AgentID: d.id, Hostname: d.id, Version: "integration-simulator", Status: "online",
			StartedAt: d.started.UTC().Format(time.RFC3339), UptimeSeconds: uint64(time.Since(d.started).Seconds()),
			Timestamp: now.Format(time.RFC3339Nano)})
	}
	if err := sendStatus(); err != nil {
		return err
	}
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	var heartbeat sync.WaitGroup
	heartbeat.Go(func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if err := sendStatus(); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	})
	defer func() { cancelHeartbeat(); _ = conn.Close(); heartbeat.Wait() }()
	var received uint64
	for {
		frame, err := fleetRead(conn)
		if err != nil {
			return err
		}
		var event, operation, signature, expected, sessionID, agentID string
		var sequence uint64
		switch frame.Type {
		case "display":
			var display protocol.Display
			if err := protocol.Decode(frame.Payload, &display); err != nil {
				return err
			}
			signature, _ := protocol.SignDisplay(display, keys[keyderivation.TransportDisplay])
			if !protocol.Verify(display.Signature, signature) || display.SessionID != welcome.SessionID || display.AgentID != d.id || display.Sequence != received+1 {
				return errors.New("protocol: invalid display control")
			}
			received = display.Sequence
			reply := protocol.Display{Protocol: protocol.Version, AgentID: d.id, SessionID: welcome.SessionID, StreamID: display.StreamID, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
			switch display.Action {
			case "prepare":
				reply.Action = "ready"
			case "open":
				reply.Action = "open"
				if err := writer.send(reply); err != nil {
					return err
				}
				reply.Action = "data"
				reply.Data = d.jpeg
			case "close":
				continue
			default:
				return errors.New("protocol: invalid display action")
			}
			if err := writer.send(reply); err != nil {
				return err
			}
			continue
		case "desired_state":
			var state protocol.DesiredState
			if err := protocol.Decode(frame.Payload, &state); err != nil {
				return err
			}
			expected, _ = protocol.SignDesiredState(state, keys[keyderivation.TransportCommand])
			signature, sessionID, agentID, sequence, event, operation = state.Signature, state.SessionID, state.AgentID, state.Sequence, state.EventID, "desired_state"
			if d.generation == state.Generation && state.Revision < d.revision {
				return errors.New("protocol: desired revision regressed")
			}
			if len(state.State.Content.ProxyAllow) != 0 {
				return errors.New("protocol: controller policy leaked into renderer state")
			}
			d.generation, d.revision = state.Generation, state.Revision
		case "command":
			var command protocol.Command
			if err := protocol.Decode(frame.Payload, &command); err != nil {
				return err
			}
			expected, _ = protocol.SignCommand(command, keys[keyderivation.TransportCommand])
			signature, sessionID, agentID, sequence, event, operation = command.Signature, command.SessionID, command.AgentID, command.Sequence, command.EventID, string(command.Command.Type())
			if _, duplicate := d.seen[event]; duplicate {
				return errors.New("protocol: command automatically repeated")
			}
			d.seen[event] = struct{}{}
			d.recent = append(d.recent, event)
			if len(d.recent) > 1024 {
				delete(d.seen, d.recent[0])
				d.recent = d.recent[1:]
			}
		default:
			return fmt.Errorf("protocol: unexpected frame %s", frame.Type)
		}
		if !protocol.Verify(signature, expected) || sessionID != welcome.SessionID || agentID != d.id || sequence != received+1 {
			return errors.New("protocol: authentication or sequence failure")
		}
		received = sequence
		receipt := protocol.Receipt{Protocol: protocol.Version, SessionID: welcome.SessionID, EventID: event, AgentID: d.id, Status: "received", Operation: operation, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := writer.send(receipt); err != nil {
			return err
		}
		receipt.Status = "completed"
		if operation == "desired_state" {
			receipt.Status = "accepted"
		}
		receipt.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writer.send(receipt); err != nil {
			return err
		}
		d.applied.Add(1)
	}
}

// TestFleetIntegration is opt-in so a normal unit run never starts a soak accidentally.
func TestFleetIntegration(t *testing.T) {
	durationText := os.Getenv("NEODSE_INTEGRATION_DURATION")
	if durationText == "" {
		t.Skip("set NEODSE_INTEGRATION_DURATION=1m to run fleet integration")
	}
	duration, err := time.ParseDuration(durationText)
	if err != nil || duration < time.Second {
		t.Fatal("invalid integration duration")
	}
	interval := time.Second
	if value := os.Getenv("NEODSE_INTEGRATION_INTERVAL"); value != "" {
		interval, err = time.ParseDuration(value)
		if err != nil || interval < time.Millisecond || interval > 30*time.Second {
			t.Fatal("integration interval must be between 1ms and 30s")
		}
	}
	raceEnabled := fleetRaceEnabled(t)
	t.Logf("fleet workload duration=%s pause_between_bursts=%s displays=100 healthy=99 race=%t", duration, interval, raceEnabled)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	path := filepath.Join(t.TempDir(), "transport.yaml")
	secret := strings.Repeat("cd", 32)
	if err := os.WriteFile(path, []byte(fmt.Sprintf("transport:\n  listen: %s\n  controller_psk: %s\n", address, secret)), 0o600); err != nil {
		t.Fatal(err)
	}
	transportDone := make(chan error, 1)
	go func() { transportDone <- transport.Run(ctx, []string{"--config", path}, "integration") }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-transportDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("transport workers did not stop")
		}
	})
	cfg := Config{Server: config.ServerSettings{TransportURL: "ws://" + address, TransportPSK: secret, EventRetentionDays: 1}}
	credentials := make(map[string]string, 100)
	for i := range 100 {
		credentials[fmt.Sprintf("display-%03d", i)] = ""
	}
	controller := testServerWithAgents(t, cfg, credentials)
	controller.clearSessions()
	controller.startBackgroundServices(ctx)
	t.Cleanup(func() { cancel(); controller.workers.Wait() })
	handler, token := testAPI(t, controller)
	_ = handler
	api := httptest.NewTLSServer(controller.controllerHandler())
	defer api.Close()
	client := api.Client()
	client.Timeout = 40 * time.Second
	defer client.CloseIdleConnections()
	failures := make(chan error, 100)
	displays := make([]*fleetDisplay, 100)
	pixels := image.NewRGBA(image.Rect(0, 0, 1280, 720))
	for y := range 720 {
		for x := range 1280 {
			i := pixels.PixOffset(x, y)
			pixels.Pix[i] = byte(x / 5)
			pixels.Pix[i+1] = byte(y / 3)
			pixels.Pix[i+2] = byte((x + y) / 8)
			pixels.Pix[i+3] = 255
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, pixels, &jpeg.Options{Quality: 82}); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() > displayChunkBytes {
		t.Fatal("fleet JPEG exceeds frame bound")
	}
	var workers sync.WaitGroup
	for i := range displays {
		d := &fleetDisplay{id: fmt.Sprintf("display-%03d", i), endpoint: cfg.Server.TransportURL, credential: strings.Repeat("ab", 32), started: time.Now(), slow: i == 99, seen: make(map[string]struct{}), failures: failures, jpeg: encoded.Bytes()}
		displays[i] = d
		workers.Go(func() { d.run(ctx) })
	}
	defer func() { cancel(); workers.Wait() }()
	fleetWait(t, failures, 15*time.Second, func() bool {
		for _, d := range displays[:99] {
			if d.applied.Load() == 0 {
				return false
			}
		}
		return true
	})
	started := time.Now()
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	baselineWorkers := runtime.NumGoroutine()
	baselineFDs, _ := os.ReadDir("/proc/self/fd")
	baselineResident := fleetResidentBytes(t)
	cycles := 0
	for time.Since(started) < duration {
		round := time.Now()
		event := fleetRequest(t, client, api.URL, token, "PUT", "/api/v1/agents/broadcast/playlist", `{"urls":["https://display.example/integration"]}`)
		fleetWaitEvent(t, controller, failures, event, 99, "accepted")
		stateLatency := time.Since(round)
		event = fleetRequest(t, client, api.URL, token, "POST", "/api/v1/agents/broadcast/banner", `{"message":"integration","severity":"info","duration_seconds":1}`)
		fleetWaitEvent(t, controller, failures, event, 99, "completed")
		bannerLatency := time.Since(round) - stateLatency
		if cycles%5 == 0 {
			reconciled := fleetReconciliation(controller, displays[:20])
			for _, d := range displays[:20] {
				d.disconnect()
			}
			fleetWait(t, failures, 15*time.Second, reconciled)
		}
		if cycles%12 == 0 {
			clock := time.Now().In(time.Local)
			fleetSchedule(t, client, api.URL, token, clock)
			controller.runSchedules(ctx, clock)
			event := "schedule-display-098-" + clock.Format("2006-01-02T15:04") + "-on"
			fleetWaitEvent(t, controller, failures, event, 1, "completed")
		}
		if cycles%18 == 0 {
			d := displays[(cycles/18)%99]
			key := make([]byte, keyderivation.PSKBytes)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			credential := hex.EncodeToString(key)
			if err := controller.store.PutAgent(ctx, d.id, credential, "10.99.0.2", true, time.Now()); err != nil {
				t.Fatal(err)
			}
			if controller.sessionFor(d.id) != nil {
				t.Fatal("rotated credential retained session authority")
			}
			applied := d.applied.Load()
			d.mu.Lock()
			d.credential = credential
			if d.conn != nil {
				_ = d.conn.Close()
			}
			d.mu.Unlock()
			fleetWait(t, failures, 15*time.Second, func() bool {
				return d.applied.Load() > applied && controller.sessionFor(d.id) != nil
			})
			t.Logf("fleet credential rotation reconciled agent=%s cycle=%d", d.id, cycles)
		}
		if cycles > 0 && cycles%24 == 0 {
			reconciled := fleetReconciliation(controller, displays[:99])
			controller.link.mu.RLock()
			connection := controller.link.conn
			controller.link.mu.RUnlock()
			if connection != nil {
				_ = connection.Close()
			}
			fleetWait(t, failures, 15*time.Second, reconciled)
		}
		displayStarted := time.Now()
		fleetDisplayRound(t, client, api.URL, token, displays[:99])
		fleetWait(t, failures, 5*time.Second, func() bool {
			controller.displayMu.Lock()
			defer controller.displayMu.Unlock()
			return len(controller.displayRelays) == 0
		})
		t.Logf("fleet JPEG viewers=99 frame_bytes=%d aggregate_bytes=%d round_duration=%s", encoded.Len(), 99*encoded.Len(), time.Since(displayStarted))
		cycles++
		if cycles%12 == 0 || cycles == 1 {
			fleetCheckOnline(t, client, api.URL, token)
			runtime.GC()
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			fds, _ := os.ReadDir("/proc/self/fd")
			resident := fleetResidentBytes(t)
			t.Logf("fleet displays=100 healthy=99 elapsed=%s cycles=%d round_latency=%s state_latency=%s banner_latency=%s heap_bytes=%d resident_bytes=%d goroutines=%d open_fds=%d", time.Since(started).Round(time.Millisecond), cycles, time.Since(round).Round(time.Millisecond), stateLatency.Round(time.Millisecond), bannerLatency.Round(time.Millisecond), memory.HeapAlloc, resident, runtime.NumGoroutine(), len(fds))
			if runtime.NumGoroutine() > baselineWorkers+400 || len(fds) > len(baselineFDs)+400 || memory.HeapAlloc > baseline.HeapAlloc+256<<20 {
				t.Fatal("fleet resource bounds exceeded")
			}
			// Race instrumentation can retain allocations until long-running
			// goroutines exit. The production-build soak checks total resident
			// growth; race stress still checks heap, descriptors, and workers.
			if !raceEnabled && resident > baselineResident+256<<20 {
				t.Fatal("fleet resident-memory growth exceeded 256 MiB")
			}
		}
		select {
		case err := <-failures:
			t.Fatal(err)
		case <-time.After(interval):
		}
	}
	t.Logf("fleet completed duration=%s cycles=%d", time.Since(started), cycles)
}

// fleetRaceEnabled records the actual compiler setting rather than trusting an environment label.
func fleetRaceEnabled(t *testing.T) bool {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("fleet binary build information unavailable")
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}

// fleetResidentBytes includes driver and race-detector allocations outside the Go heap.
func fleetResidentBytes(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		t.Fatal("process resident-memory counters unavailable")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return pages * uint64(os.Getpagesize())
}

// fleetCheckOnline verifies persisted heartbeats and live authority through the public API.
func fleetCheckOnline(t *testing.T, client *http.Client, base, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, base+"/api/v1/agents", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var agents []agentResponse
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fleet status API returned %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&agents); err != nil {
		t.Fatal(err)
	}
	if len(agents) != 100 {
		t.Fatalf("fleet status API returned %d agents", len(agents))
	}
	for _, agent := range agents {
		if agent.AgentID != "display-099" && (!agent.IsAuthenticated || agent.Status != "online") {
			t.Fatalf("healthy display lost status: %s authenticated=%t status=%s", agent.AgentID, agent.IsAuthenticated, agent.Status)
		}
	}
}

// fleetReconciliation observes new application after a connection is interrupted.
func fleetReconciliation(s *Server, displays []*fleetDisplay) func() bool {
	before := make([]uint64, len(displays))
	for i, d := range displays {
		before[i] = d.applied.Load()
	}
	return func() bool {
		for i, d := range displays {
			if d.applied.Load() <= before[i] || s.sessionFor(d.id) == nil {
				return false
			}
		}
		return true
	}
}

// fleetRequest sends through production authorization, routing, validation, and storage.
func fleetRequest(t *testing.T, client *http.Client, base, token, method, path, body string) string {
	t.Helper()
	request, err := http.NewRequest(method, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("%s %s status=%d response=%s", method, path, response.StatusCode, payload)
	}
	var result struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(payload, &result); err != nil || result.EventID == "" {
		t.Fatal("missing accepted event")
	}
	return result.EventID
}

// fleetWaitEvent requires healthy displays to advance despite the deliberately stalled peer.
func fleetWaitEvent(t *testing.T, s *Server, failures <-chan error, event string, count int, status string) {
	t.Helper()
	fleetWait(t, failures, 10*time.Second, func() bool {
		state, err := s.store.Event(context.Background(), event)
		if err != nil {
			t.Fatal(err)
		}
		completed := 0
		for _, delivery := range state.Deliveries {
			if delivery.AgentID != "display-099" && delivery.Status == status {
				completed++
			}
		}
		return completed == count
	})
}

// fleetWait bounds progress checks and reports protocol failures immediately.
func fleetWait(t *testing.T, failures <-chan error, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for !ready() {
		select {
		case err := <-failures:
			t.Fatal(err)
		case <-deadline.C:
			t.Fatal("healthy fleet progress deadline exceeded")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// fleetSchedule configures a due hardware action through the authenticated public API.
func fleetSchedule(t *testing.T, client *http.Client, base, token string, now time.Time) {
	t.Helper()
	value := store.Schedule{Days: []string{strings.ToLower(now.Weekday().String())}, PowerOn: now.Format("15:04"), PowerOff: now.Add(10 * time.Minute).Format("15:04"), Enabled: true}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, base+"/api/v1/agents/display-098/schedules", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("schedule API status=%d", response.StatusCode)
	}
}

// fleetDisplayRound reads framed JPEG streams from every healthy simulated agent.
func fleetDisplayRound(t *testing.T, client *http.Client, base, token string, displays []*fleetDisplay) {
	t.Helper()
	var workers sync.WaitGroup
	for _, display := range displays {
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/agents/"+display.id+"/display/stream", nil)
			if err != nil {
				t.Error(err)
				return
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := client.Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
				t.Errorf("%s stream status=%d response=%q read_error=%v", display.id, response.StatusCode, body, readErr)
				return
			}
			var length [4]byte
			if _, err := io.ReadFull(response.Body, length[:]); err != nil {
				t.Errorf("%s stream frame header: %v", display.id, err)
				return
			}
			size := binary.BigEndian.Uint32(length[:])
			if size == 0 || size > displayChunkBytes {
				t.Errorf("invalid JPEG length=%d", size)
				return
			}
			data := make([]byte, size)
			if _, err := io.ReadFull(response.Body, data); err != nil {
				t.Errorf("%s stream frame payload: %v", display.id, err)
				return
			}
			if !bytes.Equal(data, display.jpeg) {
				t.Error("JPEG changed across relay")
				return
			}
			// Exact byte equality above already verifies the encoded fixture.
			// Avoid decoding 99 identical pixel buffers on the same scheduler
			// that must also keep the controller and transport responsive.
			frame, err := jpeg.DecodeConfig(bytes.NewReader(data))
			if err != nil || frame.Width != 1280 || frame.Height != 720 {
				t.Errorf("invalid display JPEG: %v", err)
			}
		})
	}
	workers.Wait()
	if t.Failed() {
		t.FailNow()
	}
}
