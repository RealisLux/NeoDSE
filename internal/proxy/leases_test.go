// File purpose: Exercises shared leases and revocation of real HTTP streams.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

// TestConnectRevocationAndShutdown exercises hijacked sockets through the real proxy.
func TestConnectRevocationAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%t", shutdown), func(t *testing.T) {
			var revoked atomic.Bool
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(wire.AuthorizeResponse{Authenticated: true, Allowed: !revoked.Load()})
			}))
			defer backend.Close()
			p := &Proxy{backendClient: backend.Client(), internalToken: "test", leaseDuration: 200 * time.Millisecond}
			p.config.Proxy.BackendURL = backend.URL
			upstreamClosed := make(chan struct{})
			p.dialOverride = func(context.Context, string, string) (net.Conn, error) {
				client, upstream := net.Pipe()
				go func() { defer close(upstreamClosed); defer upstream.Close(); _, _ = io.Copy(upstream, upstream) }()
				return client, nil
			}
			server := httptest.NewServer(http.HandlerFunc(p.handleProxy))
			defer server.Close()
			defer p.stopLeases()
			client, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			credentials := base64.StdEncoding.EncodeToString([]byte("display:" + strings.Repeat("ab", 32)))
			_, err = fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\nearly", credentials)
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(client)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("CONNECT status=%d", response.StatusCode)
			}
			data := make([]byte, 5)
			if _, err := io.ReadFull(reader, data); err != nil || string(data) != "early" {
				t.Fatalf("buffered tunnel data lost: %q, %v", data, err)
			}
			started := time.Now()
			if shutdown {
				p.stopLeases()
			} else {
				revoked.Store(true)
			}
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("revoked tunnel remained open")
			}
			if time.Since(started) > time.Second {
				t.Fatal("tunnel closure exceeded authorization bound")
			}
			select {
			case <-upstreamClosed:
			case <-time.After(time.Second):
				t.Fatal("upstream copy worker leaked")
			}
		})
	}
}

// TestActiveHTTPStreamsLoseAuthorization verifies shared renewals close all consumers.
func TestActiveHTTPStreamsLoseAuthorization(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "backend failure"}[unavailable], func(t *testing.T) {
			var revoke atomic.Bool
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if revoke.Load() && unavailable {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(wire.AuthorizeResponse{Authenticated: true, Allowed: !revoke.Load()})
			}))
			defer backend.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("ready\n"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer upstream.Close()
			p := &Proxy{backendClient: backend.Client(), internalToken: "test", leaseDuration: 200 * time.Millisecond}
			p.config.Proxy.BackendURL = backend.URL
			upstreamURL, _ := url.Parse(upstream.URL)
			p.proxyClient = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstreamURL.Host)
			}}}
			defer p.proxyClient.CloseIdleConnections()
			proxyServer := httptest.NewServer(http.HandlerFunc(p.handleProxy))
			defer proxyServer.Close()
			defer p.stopLeases()
			proxyURL, _ := url.Parse(proxyServer.URL)
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			defer client.CloseIdleConnections()
			var responses []*http.Response
			for range 2 {
				req, _ := http.NewRequest(http.MethodGet, "http://content.example/stream", nil)
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("display:"+strings.Repeat("ab", 32))))
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				first := make([]byte, 6)
				if _, err := io.ReadFull(response.Body, first); err != nil {
					t.Fatal(err)
				}
				responses = append(responses, response)
			}
			p.leaseMu.Lock()
			groups := len(p.leases)
			p.leaseMu.Unlock()
			if groups != 1 {
				t.Fatalf("lease groups=%d", groups)
			}
			revoke.Store(true)
			for _, response := range responses {
				started := time.Now()
				_, _ = io.ReadAll(response.Body)
				if time.Since(started) > time.Second {
					t.Fatal("revoked stream exceeded lease bound")
				}
			}
		})
	}
}

// TestShutdownInterruptsStalledHTTPUpload joins the forwarding worker even when
// a client sends only part of its request body and keeps the connection open.
func TestShutdownInterruptsStalledHTTPUpload(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.AuthorizeResponse{Authenticated: true, Allowed: true})
	}))
	defer backend.Close()
	uploadStarted := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var first [1]byte
		if _, err := io.ReadFull(r.Body, first[:]); err != nil {
			return
		}
		close(uploadStarted)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer upstream.Close()
	p := &Proxy{backendClient: backend.Client(), internalToken: "test"}
	p.config.Proxy.BackendURL = backend.URL
	upstreamURL, _ := url.Parse(upstream.URL)
	p.proxyClient = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamURL.Host)
	}}}
	defer p.proxyClient.CloseIdleConnections()
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(p.handleProxy))
	proxyServer.Config.ReadTimeout = 5 * time.Second
	proxyServer.Start()
	defer proxyServer.Close()
	client, err := net.DialTimeout("tcp", proxyServer.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer p.stopLeases()
	credentials := base64.StdEncoding.EncodeToString([]byte("display:" + strings.Repeat("ab", 32)))
	if _, err := fmt.Fprintf(client, "POST http://content.example/upload HTTP/1.1\r\nHost: content.example\r\nContent-Length: 1048576\r\nProxy-Authorization: Basic %s\r\n\r\n%s", credentials, strings.Repeat("x", 16<<10)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not begin forwarding the upload")
	}
	stopped := make(chan struct{})
	go func() {
		p.stopLeases()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		_ = client.Close()
		<-stopped
		t.Fatal("proxy shutdown waited for the stalled client's read timeout")
	}
}

// TestLeaseLimitFollowsConfiguredConnections verifies that distinct leases are
// bounded by the configured fleet connection limit, not a smaller fixed cap.
func TestLeaseLimitFollowsConfiguredConnections(t *testing.T) {
	for _, limit := range []int{2, 1500} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			p := &Proxy{connections: make(chan struct{}, limit)}
			defer p.stopLeases()
			for index := range limit + 1 {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request := &proxyRequest{ctx: ctx, cancel: cancel, agentID: "display", token: strings.Repeat("ab", 32), authorizedAt: time.Now()}
				bound := p.bindLease(request, proxyTarget{scheme: "https", host: fmt.Sprintf("content-%d.example", index), port: "443"})
				if bound != (index < limit) {
					t.Fatalf("lease %d with connection limit %d bound=%t", index+1, limit, bound)
				}
				if bound {
					defer request.releaseLease()
				}
			}
		})
	}
}

// TestLeaseExpiryInterruptsSlowRenewal proves a late allowed response cannot extend authority.
func TestLeaseExpiryInterruptsSlowRenewal(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); <-r.Context().Done() }))
	defer backend.Close()
	p := &Proxy{backendClient: backend.Client(), internalToken: "test", leaseDuration: 100 * time.Millisecond}
	p.config.Proxy.BackendURL = backend.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := &proxyRequest{ctx: ctx, cancel: cancel, agentID: "display", token: strings.Repeat("ab", 32), authorizedAt: time.Now()}
	if !p.bindLease(request, proxyTarget{scheme: "https", host: "example.com", port: "443"}) {
		t.Fatal("lease denied")
	}
	defer request.releaseLease()
	defer p.stopLeases()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("hard lease deadline missed")
	}
}
