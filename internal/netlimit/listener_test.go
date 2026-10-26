// File purpose: Verifies pre-HTTP connection admission, source isolation, and connection lifetime accounting.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package netlimit

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewRejectsInvalidCapacity verifies invalid limits cannot disable admission.
func TestNewRejectsInvalidCapacity(t *testing.T) {
	for _, limits := range [][2]int{{0, 1}, {1, 0}, {-1, 1}, {1, -1}} {
		if _, err := New(limits[0], limits[1]); err == nil {
			t.Fatalf("accepted invalid limits %v", limits)
		}
	}
}

// TestListenersShareCapacity verifies one source cannot consume a healthy
// source's capacity through another listener or an IPv4-mapped address.
func TestListenersShareCapacity(t *testing.T) {
	pool := newTestPool(t, 2, 1)
	first := newTrackedConn(t, "10.0.0.2:1000")
	duplicate := newTrackedConn(t, "[::ffff:10.0.0.2]:1001")
	healthy := newTrackedConn(t, "10.0.0.3:1002")
	overflow := newTrackedConn(t, "10.0.0.4:1003")
	replacement := newTrackedConn(t, "10.0.0.2:1004")
	firstListener := pool.Wrap(newQueuedListener(first, overflow, replacement))
	secondListener := pool.Wrap(newQueuedListener(duplicate, healthy))
	acceptedFirst, err := firstListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	acceptedHealthy, err := secondListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.closes.Load() != 1 {
		t.Fatal("the same source bypassed its quota through another listener")
	}
	// Both pending connections are rejected at the total limit. A later
	// connection from the first source can enter once its active one closes.
	if _, err := firstListener.Accept(); !errors.Is(err, errAcceptDone) {
		t.Fatalf("full pool accept = %v", err)
	}
	if overflow.closes.Load() != 1 || replacement.closes.Load() != 1 {
		t.Fatal("total capacity did not close excess connections immediately")
	}
	if err := acceptedFirst.Close(); err != nil {
		t.Fatal(err)
	}
	replacementListener := pool.Wrap(newQueuedListener(newTrackedConn(t, "10.0.0.2:1005")))
	acceptedReplacement, err := replacementListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = acceptedHealthy.Close()
	_ = acceptedReplacement.Close()
	assertEmptyPool(t, pool)
}

// TestLoopbackExemptionStillBoundsTotal verifies local relays can carry
// multiple agents without bypassing the total connection limit.
func TestLoopbackExemptionStillBoundsTotal(t *testing.T) {
	pool := newTestPool(t, 2, 1)
	first := newTrackedConn(t, "127.0.0.1:1000")
	second := newTrackedConn(t, "[::1]:1001")
	third := newTrackedConn(t, "[::ffff:127.0.0.1]:1002")
	listener := pool.Wrap(newQueuedListener(first, second, third))
	for range 2 {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	if _, err := listener.Accept(); !errors.Is(err, errAcceptDone) {
		t.Fatalf("full loopback pool accept = %v", err)
	}
	if third.closes.Load() != 1 || len(pool.sources) != 0 {
		t.Fatal("loopback exemption bypassed total capacity or retained source entries")
	}
}

// TestUnknownSourceIsRejected verifies missing or nonnumeric addresses cannot
// select an unbounded quota or grow accounting for rejected connections.
func TestUnknownSourceIsRejected(t *testing.T) {
	pool := newTestPool(t, 1, 1)
	missing := newTrackedConn(t, "")
	invalid := newTrackedConn(t, "agent.example:1000")
	healthy := newTrackedConn(t, "10.0.0.2:1000")
	listener := pool.Wrap(newQueuedListener(missing, invalid, healthy))
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if missing.closes.Load() != 1 || invalid.closes.Load() != 1 {
		t.Fatal("unknown source was admitted")
	}
	_ = conn.Close()
	assertEmptyPool(t, pool)
}

// TestCloseReleasesOnceOnError verifies concurrent close calls return the
// original close error and release both quotas exactly once.
func TestCloseReleasesOnceOnError(t *testing.T) {
	pool := newTestPool(t, 1, 1)
	raw := newTrackedConn(t, "10.0.0.2:1000")
	raw.closeErr = errors.New("connection close failed")
	conn, err := pool.Wrap(newQueuedListener(raw)).Accept()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			if err := conn.Close(); !errors.Is(err, raw.closeErr) {
				t.Errorf("close error = %v", err)
			}
		})
	}
	workers.Wait()
	if raw.closes.Load() != 1 {
		t.Fatalf("underlying close calls = %d", raw.closes.Load())
	}
	assertEmptyPool(t, pool)
}

// TestListenerClosePreservesAcceptedConnections verifies listener shutdown
// unblocks Accept without forgetting still-open connections owned by callers.
func TestListenerClosePreservesAcceptedConnections(t *testing.T) {
	pool := newTestPool(t, 1, 1)
	queued := newQueuedListener(newTrackedConn(t, "10.0.0.2:1000"))
	listener := pool.Wrap(queued)
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// Remove the fixture's terminal error so this Accept blocks until Close.
	<-queued.results
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed listener accept = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener close did not unblock Accept")
	}
	if pool.active != 1 {
		t.Fatal("closing a listener released a still-open accepted connection")
	}
	_ = conn.Close()
	assertEmptyPool(t, pool)
}

// TestConcurrentAdmissionRemainsBounded verifies concurrent accepts and
// closes keep shared accounting bounded and remove inactive source entries.
func TestConcurrentAdmissionRemainsBounded(t *testing.T) {
	pool := newTestPool(t, 8, 2)
	connections := make([]*trackedConn, 256)
	for index := range connections {
		connections[index] = newTrackedConn(t, fmt.Sprintf("10.0.0.%d:%d", index%4+2, index+1000))
	}
	queued := newQueuedListener(connections...)
	for range 15 {
		queued.results <- acceptResult{err: errAcceptDone}
	}
	listener := pool.Wrap(queued)
	accepted := make(chan net.Conn, len(connections))
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for {
				conn, err := listener.Accept()
				if errors.Is(err, errAcceptDone) {
					return
				}
				if err != nil {
					t.Errorf("accept: %v", err)
					return
				}
				accepted <- conn
			}
		})
	}
	workers.Wait()
	close(accepted)
	if len(accepted) != 8 || pool.active != 8 || len(pool.sources) != 4 {
		t.Fatalf("accepted=%d active=%d sources=%v", len(accepted), pool.active, pool.sources)
	}
	for _, count := range pool.sources {
		if count != 2 {
			t.Fatalf("source connection count = %d", count)
		}
	}
	for conn := range accepted {
		workers.Go(func() { _ = conn.Close() })
	}
	workers.Wait()
	assertEmptyPool(t, pool)
	for _, conn := range connections {
		if conn.closes.Load() != 1 {
			t.Fatalf("connection close count = %d", conn.closes.Load())
		}
	}
}

// TestPartialHTTPConnectionsAreLimitedBeforeParsing verifies incomplete HTTP
// headers consume admission capacity and excess sockets close immediately.
func TestPartialHTTPConnectionsAreLimitedBeforeParsing(t *testing.T) {
	pool := newTestPool(t, 4, 1)
	listener := listenForTest(t)
	opened := make(chan struct{}, 4)
	closed := make(chan struct{}, 4)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				opened <- struct{}{}
			} else if state == http.StateClosed {
				closed <- struct{}{}
			}
		},
	}
	serveForTest(t, server, pool.Wrap(sourceListener{Listener: listener, remote: testAddress("10.0.0.2:1000")}))
	first := dialForTest(t, listener.Addr().String())
	awaitSignal(t, opened)
	if _, err := io.WriteString(first, "GET / HTTP/1.1\r\nHost: controller\r\n"); err != nil {
		t.Fatal(err)
	}
	rejected := dialForTest(t, listener.Addr().String())
	assertConnectionClosed(t, rejected)
	select {
	case <-opened:
		t.Fatal("excess connection reached HTTP parsing")
	default:
	}
	_ = first.Close()
	awaitSignal(t, closed)
	replacement := dialForTest(t, listener.Addr().String())
	awaitSignal(t, opened)
	_ = replacement.Close()
	awaitSignal(t, closed)
	assertEmptyPool(t, pool)
}

// TestHijackedConnectionRetainsCapacity verifies upgraded protocols retain
// their admission slot until their owner closes the hijacked connection.
func TestHijackedConnectionRetainsCapacity(t *testing.T) {
	pool := newTestPool(t, 1, 1)
	listener := listenForTest(t)
	hijacked := make(chan net.Conn, 2)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			conn, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			hijacked <- conn
		}),
	}
	serveForTest(t, server, pool.Wrap(listener))
	client := dialForTest(t, listener.Addr().String())
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: controller\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	select {
	case conn = <-hijacked:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP connection was not hijacked")
	}
	t.Cleanup(func() { _ = conn.Close() })
	rejected := dialForTest(t, listener.Addr().String())
	assertConnectionClosed(t, rejected)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if pool.active != 1 {
		t.Fatal("server shutdown released an open hijacked connection")
	}
	_ = conn.Close()
	assertEmptyPool(t, pool)
}

var errAcceptDone = errors.New("test accept queue exhausted")

type acceptResult struct {
	conn net.Conn
	err  error
}

type queuedListener struct {
	results chan acceptResult
	closed  chan struct{}
	close   sync.Once
}

func newQueuedListener(connections ...*trackedConn) *queuedListener {
	listener := &queuedListener{
		results: make(chan acceptResult, len(connections)+16),
		closed:  make(chan struct{}),
	}
	for _, conn := range connections {
		listener.results <- acceptResult{conn: conn}
	}
	listener.results <- acceptResult{err: errAcceptDone}
	return listener
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case result := <-l.results:
		return result.conn, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	l.close.Do(func() { close(l.closed) })
	return nil
}

func (l *queuedListener) Addr() net.Addr { return testAddress("127.0.0.1:1000") }

type testAddress string

func (a testAddress) Network() string { return "tcp" }
func (a testAddress) String() string  { return string(a) }

type trackedConn struct {
	net.Conn
	remote   net.Addr
	closes   atomic.Int32
	closeErr error
}

func newTrackedConn(t *testing.T, remote string) *trackedConn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	conn := &trackedConn{Conn: server}
	if remote != "" {
		conn.remote = testAddress(remote)
	}
	return conn
}

func (c *trackedConn) RemoteAddr() net.Addr { return c.remote }

func (c *trackedConn) Close() error {
	c.closes.Add(1)
	_ = c.Conn.Close()
	return c.closeErr
}

type sourceListener struct {
	net.Listener
	remote net.Addr
}

func (l sourceListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: conn, remote: l.remote}, nil
}

func newTestPool(t *testing.T, total, perSource int) *Pool {
	t.Helper()
	pool, err := New(total, perSource)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func assertEmptyPool(t *testing.T, pool *Pool) {
	t.Helper()
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.active != 0 || len(pool.sources) != 0 {
		t.Fatalf("retained connection accounting: active=%d sources=%v", pool.active, pool.sources)
	}
}

func listenForTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func dialForTest(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func assertConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := conn.Read(buffer[:]); err == nil {
		t.Fatal("excess connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection timed out instead of closing immediately")
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("connection state did not change")
	}
}

func serveForTest(t *testing.T, server *http.Server, listener net.Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("HTTP server did not stop")
		}
	})
}
