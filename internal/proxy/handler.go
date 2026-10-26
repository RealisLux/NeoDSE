// File purpose: Coordinates authenticated HTTP forwarding and CONNECT tunnels through small fail-closed stages.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/RealisLux/NeoDSE/internal/destination"
)

type proxyRequest struct {
	ctx                context.Context
	cancel             context.CancelFunc
	releaseLease       func()
	agentSlot          bool
	authorizedAt       time.Time
	id                 uint64
	started            time.Time
	agentID            string
	token              string
	outcome            string
	loggedAgentID      string
	destinationHost    string
	destinationPort    string
	protocol           string
	bytesToDestination int64
	bytesToClient      int64
}

type proxyTarget struct {
	scheme  string
	host    string
	port    string
	address string
}

// setLoggedTarget records only a destination that the controller authenticated and validated.
func setLoggedTarget(request *proxyRequest, target proxyTarget) {
	request.destinationHost = target.host
	request.destinationPort = target.port
	request.protocol = target.scheme
}

type tunnelCopyResult struct {
	direction string
	bytes     int64
	err       error
}

// handleProxy applies connection limits and authentication before selecting one forwarding mode.
func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	request := proxyRequest{id: p.requestID.Add(1), started: time.Now(), ctx: ctx, cancel: cancel}
	if !p.trackRequest(request.id, cancel) {
		http.Error(w, "proxy stopping", http.StatusServiceUnavailable)
		return
	}
	defer p.releaseRequest(request.id)
	// Cancellation must interrupt both a stalled upload and a client that
	// stopped consuming the response before shutdown joins forwarding workers.
	if r.Method != http.MethodConnect {
		ioStopped := make(chan struct{})
		stopIO := context.AfterFunc(ctx, func() {
			response := http.NewResponseController(w)
			_ = response.SetReadDeadline(time.Now())
			_ = response.SetWriteDeadline(time.Now())
			close(ioStopped)
		})
		defer func() {
			if !stopIO() {
				<-ioStopped
			}
		}()
	}

	defer func() {
		if request.releaseLease != nil {
			request.releaseLease()
		}
		if request.agentSlot {
			p.releaseAgentConnection(request.agentID)
		}
	}()
	defer p.logRequestSummary(&request)

	if !p.acquireConnection() {
		request.outcome = "capacity_rejected"
		p.logCapacityRejection("fleet", "proxy.max_connections")
		http.Error(w, "proxy capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer p.releaseConnection()

	var credentialReason string
	request.agentID, request.token, credentialReason = p.proxyCredentials(r)
	if credentialReason != "" {
		request.outcome = "authentication_required"
		writeProxyAuthenticationRequired(w)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, &request)
		return
	}
	p.handleHTTP(w, r, &request)
}

// acquireConnection reserves one global proxy slot; a nil limiter means unlimited test capacity.
func (p *Proxy) acquireConnection() bool {
	if p.connections == nil {
		return true
	}
	select {
	case p.connections <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseConnection releases a global slot reserved by acquireConnection.
func (p *Proxy) releaseConnection() {
	if p.connections != nil {
		<-p.connections
	}
}

// handleHTTP validates an absolute target, authorizes it, and streams one HTTP response.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, request *proxyRequest) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	target, err := parseHTTPProxyTarget(r)
	if err != nil {
		request.outcome = "invalid_target"
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.authorizeTarget(w, request, target) {
		return
	}
	p.forwardHTTP(w, r, request, target)
}

// parseHTTPProxyTarget accepts only absolute HTTP(S) request targets without user information and supplies the default port.
func parseHTTPProxyTarget(r *http.Request) (proxyTarget, error) {
	if !r.URL.IsAbs() || r.URL.Hostname() == "" || r.URL.User != nil {
		return proxyTarget{}, errors.New("absolute HTTP URL required")
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return proxyTarget{}, errors.New("unsupported proxy URL scheme")
	}
	return canonicalTarget(r.URL.Scheme, r.URL.Hostname(), destination.URLPort(r.URL))
}

// authorizeTarget converts backend decisions into the only permitted client responses.
func (p *Proxy) authorizeTarget(w http.ResponseWriter, request *proxyRequest, target proxyTarget) bool {
	request.authorizedAt = time.Now()
	decision := p.authorize(request.ctx, request.id, request.agentID, request.token, target.host, target.port, target.scheme)
	switch decision {
	case authorizationAllowed:
		// Only the authority's authenticated identity may consume a display's
		// quota. Bad credentials cannot reserve another display's slots.
		if !p.acquireAgentConnection(request.agentID) {
			request.outcome = "capacity_rejected"
			p.logCapacityRejection("display", "proxy.max_agent_connections")
			http.Error(w, "agent proxy capacity reached", http.StatusServiceUnavailable)
			return false
		}
		request.agentSlot = true
		if !p.bindLease(request, target) {
			request.outcome = "authorization_unavailable"
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			return false
		}
		setLoggedTarget(request, target)
		request.loggedAgentID = request.agentID
		return true
	case authorizationCredentialsRejected:
		request.outcome = "authentication_required"
		writeProxyAuthenticationRequired(w)
	case authorizationDenied:
		setLoggedTarget(request, target)
		request.loggedAgentID = request.agentID
		request.outcome = "authorization_denied"
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		request.outcome = "authorization_unavailable"
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
	}
	return false
}

// forwardHTTP removes hop-by-hop data and streams one authorized upstream response.
func (p *Proxy) forwardHTTP(w http.ResponseWriter, r *http.Request, request *proxyRequest, target proxyTarget) {
	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	// Bind both the dial target and HTTP Host header to the destination the
	// controller authorized. A client-supplied Host header must not select a
	// different virtual host on a shared upstream address.
	outbound.URL.Scheme = target.scheme
	outbound.URL.Host = target.address
	outbound.Host = target.address
	removeHopByHopHeaders(outbound.Header)

	// #nosec G704 -- EXC-PROXY-AUTHORIZED-DIAL: authorization precedes one filtered resolution and a direct approved-IP dial.
	response, err := p.proxyClient.Do(outbound)
	if err != nil {
		request.outcome = "upstream_failed"
		log.Printf("! Proxy upstream request failed request_id=%d agent=%s target=%s", request.id, request.loggedAgentID, target.address)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopByHopHeaders(response.Header)
	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	bytesCopied, copyErr := io.Copy(streamWriter{ResponseWriter: w, streaming: response.ContentLength < 0}, response.Body)
	request.bytesToClient = bytesCopied
	if copyErr != nil {
		request.outcome = "stream_failed"
		log.Printf("! Proxy response stream failed request_id=%d agent=%s bytes=%d", request.id, request.loggedAgentID, bytesCopied)
		// Headers already reached the client. Abort the response so net/http
		// cannot mark a truncated chunked body as successfully completed.
		// handleProxy's deferred cleanup still releases slots and logs the outcome.
		panic(http.ErrAbortHandler)
	}
	request.outcome = "completed"
}

// handleConnect parses, authorizes, and dials one HTTPS tunnel target.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, request *proxyRequest) {
	target, err := parseConnectTarget(r.Host)
	if err != nil {
		request.outcome = "invalid_target"
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	if !p.authorizeTarget(w, request, target) {
		return
	}
	dialContext, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	upstream, err := p.dialDestination(dialContext, "tcp", target.address)
	if err != nil {
		request.outcome = "upstream_failed"
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	p.establishTunnel(w, upstream, request, target)
}

// parseConnectTarget requires the standard host:port authority form.
func parseConnectTarget(authority string) (proxyTarget, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" || port == "" {
		return proxyTarget{}, errors.New("invalid CONNECT target")
	}
	return canonicalTarget("https", host, port)
}

// establishTunnel takes ownership of the hijacked client connection for a bounded relay.
func (p *Proxy) establishTunnel(w http.ResponseWriter, upstream net.Conn, request *proxyRequest, target proxyTarget) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		request.outcome = "tunnel_failed"
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		request.outcome = "tunnel_failed"
		log.Printf("! Proxy CONNECT hijack failed request_id=%d agent=%s", request.id, request.loggedAgentID)
		return
	}
	defer client.Close()
	stopClose := context.AfterFunc(request.ctx, func() { _ = client.Close(); _ = upstream.Close() })
	defer stopClose()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		request.outcome = "tunnel_failed"
		return
	}
	if err := buffered.Flush(); err != nil {
		request.outcome = "tunnel_failed"
		return
	}
	if buffered.Reader.Buffered() > 0 {
		_ = upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.CopyN(upstream, buffered.Reader, int64(buffered.Reader.Buffered())); err != nil {
			return
		}
	}
	results := p.relayTunnel(client, upstream, request, tunnelIdleTimeout)
	request.outcome = "completed"
	for _, result := range results {
		if result.direction == "client_to_upstream" {
			request.bytesToDestination = result.bytes
		} else {
			request.bytesToClient = result.bytes
		}
	}
	if results[0].err != nil {
		request.outcome = "stream_failed"
	}
}

// tunnelIdleTimeout closes a tunnel that carries no data in either direction.
const tunnelIdleTimeout = 5 * time.Minute

// tunnelActivity records the latest transfer in either tunnel direction, so a
// one-way stream such as a long download or server-sent events stays open while
// its other direction is silent. Offsets use the monotonic clock.
type tunnelActivity struct {
	opened time.Time
	last   atomic.Int64
}

// newTunnelActivity starts the shared idle clock when a tunnel opens.
func newTunnelActivity() *tunnelActivity {
	return &tunnelActivity{opened: time.Now()}
}

// touch records a transfer in either direction.
func (activity *tunnelActivity) touch() {
	activity.last.Store(int64(time.Since(activity.opened)))
}

// deadline returns when the tunnel becomes idle unless more data is transferred.
func (activity *tunnelActivity) deadline(idle time.Duration) time.Time {
	return activity.opened.Add(time.Duration(activity.last.Load()) + idle)
}

// relayTunnel copies both directions until one side closes, neither direction
// transfers data for the idle timeout, or four hours elapse.
func (p *Proxy) relayTunnel(client, upstream net.Conn, request *proxyRequest, idle time.Duration) []tunnelCopyResult {
	done := make(chan tunnelCopyResult, 2)
	absoluteTimer := time.AfterFunc(4*time.Hour, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer absoluteTimer.Stop()
	activity := newTunnelActivity()
	go copyTunnel(done, "client_to_upstream", upstream, client, idle, activity)
	go copyTunnel(done, "upstream_to_client", client, upstream, idle, activity)
	first := <-done
	_ = client.Close()
	_ = upstream.Close()
	second := <-done
	if first.err != nil {
		log.Printf("! Proxy CONNECT stream ended request_id=%d agent=%s direction=%s bytes=%d", request.id, request.loggedAgentID, first.direction, first.bytes)
	}
	return []tunnelCopyResult{first, second}
}

// copyTunnel reports completion of one tunnel direction without blocking its peer.
func copyTunnel(done chan<- tunnelCopyResult, direction string, destination, source net.Conn, idle time.Duration, activity *tunnelActivity) {
	bytesCopied, err := copyWithIdleDeadline(destination, source, idle, activity)
	done <- tunnelCopyResult{direction: direction, bytes: bytesCopied, err: err}
}

// copyWithIdleDeadline streams bytes until the shared activity clock reports
// that neither direction has transferred data for the idle period. Each write
// must still make progress within the idle period.
func copyWithIdleDeadline(destination, source net.Conn, idle time.Duration, activity *tunnelActivity) (int64, error) {
	if idle <= 0 {
		return 0, errors.New("invalid proxy tunnel idle timeout")
	}
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		_ = source.SetReadDeadline(activity.deadline(idle))
		count, readErr := source.Read(buffer)
		if count > 0 {
			activity.touch()
			written, writeErr := writeAllWithDeadline(destination, buffer[:count], idle)
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			// The other direction may have transferred data while this read waited.
			if errors.Is(readErr, os.ErrDeadlineExceeded) && time.Now().Before(activity.deadline(idle)) {
				continue
			}
			return total, readErr
		}
	}
}

// writeAllWithDeadline handles short writes while maintaining the tunnel idle deadline.
func writeAllWithDeadline(destination net.Conn, data []byte, idle time.Duration) (int, error) {
	written := 0
	for written < len(data) {
		_ = destination.SetWriteDeadline(time.Now().Add(idle))
		count, err := destination.Write(data[written:])
		written += count
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

// writeProxyAuthenticationRequired returns the standard renewable Basic-auth challenge.
func writeProxyAuthenticationRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="NeoDSE"`)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

// canonicalTarget ensures dialing and policy use identical destination identities.
func canonicalTarget(scheme, host, port string) (proxyTarget, error) {
	value, err := destination.Canonical(scheme, host, port)
	if err != nil {
		return proxyTarget{}, err
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return proxyTarget{}, err
	}
	return proxyTarget{scheme: parsed.Scheme, host: parsed.Hostname(), port: parsed.Port(), address: parsed.Host}, nil
}

// streamWriter flushes unknown-length responses so live content is not buffered indefinitely.
type streamWriter struct {
	http.ResponseWriter
	streaming bool
}

// Write forwards bytes and flushes incremental responses under the server write deadline.
func (w streamWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil && w.streaming {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}
