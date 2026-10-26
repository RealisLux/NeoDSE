// File purpose: Verifies bounded queues isolate slow peers and release every reservation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestSlowPeerCannotBlockHealthyWrites saturates a real socket with an unread client.
func TestSlowPeerCannotBlockHealthyWrites(t *testing.T) {
	var budget atomic.Int64
	var handlers sync.WaitGroup
	accepted := make(chan *peer, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		p := &peer{conn: conn}
		p.start(&budget, 32, peerQueueBytes)
		handlers.Add(1)
		defer handlers.Done()
		accepted <- p
		<-p.done
		p.close()
	}))
	defer server.Close()
	var peers []*peer
	defer func() {
		for _, p := range peers {
			p.stop()
		}
		handlers.Wait()
	}()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	slow, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	slowPeer := <-accepted
	peers = append(peers, slowPeer)
	healthy, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	healthyPeer := <-accepted
	peers = append(peers, healthyPeer)
	payload := strings.Repeat("x", 512<<10)
	started := time.Now()
	saturated := false
	for range 64 {
		if err := slowPeer.writeJSON(payload); err != nil {
			saturated = true
			break
		}
	}
	if !saturated {
		t.Fatal("slow peer queue did not reach a bound")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("slow peer blocked caller")
	}
	if budget.Load() > serviceQueueBytes || slowPeer.queued.Load() > peerQueueBytes {
		t.Fatal("queue memory exceeded limit")
	}
	if err := healthyPeer.writeJSON("healthy"); err != nil {
		t.Fatal(err)
	}
	_ = healthy.SetReadDeadline(time.Now().Add(time.Second))
	var received string
	if err := healthy.ReadJSON(&received); err != nil || received != "healthy" {
		t.Fatalf("healthy peer stalled: %q %v", received, err)
	}
	for _, p := range peers {
		p.close()
	}
	if budget.Load() != 0 {
		t.Fatalf("queue reservation leaked: %d", budget.Load())
	}
}
