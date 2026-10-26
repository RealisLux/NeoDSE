// File purpose: Owns bounded asynchronous WebSocket writes and peer shutdown.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package transport

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const peerQueueBytes = 8 << 20
const serviceQueueBytes = 64 << 20

type peer struct {
	connectionID string
	conn         *websocket.Conn
	queueMu      sync.Mutex
	once         sync.Once
	approval     sync.Once
	done         chan struct{}
	approved     chan struct{}
	queue        chan []byte
	rejections   chan string
	handshake    *time.Timer
	workers      sync.WaitGroup
	queued       atomic.Int64
	budget       *atomic.Int64
	byteLimit    int64
}

// start initializes all reader settings before the read loop starts.
func (p *peer) start(budget *atomic.Int64, frames int, bytes int64) {
	p.byteLimit = bytes
	p.done = make(chan struct{})
	p.approved = make(chan struct{})
	p.queue = make(chan []byte, frames)
	p.rejections = make(chan string, 1)
	p.budget = budget
	p.conn.SetReadLimit(maxMessageBytes)
	_ = p.conn.SetReadDeadline(time.Now().Add(pongTimeout))
	p.conn.SetPongHandler(func(string) error { return p.conn.SetReadDeadline(time.Now().Add(pongTimeout)) })
	p.workers.Go(p.writeLoop)
	p.workers.Go(p.keepalive)
}

// approve admits active traffic only after the trusted controller queues its
// first reply, completing this peer's end-to-end authentication barrier.
func (p *peer) approve() {
	if p.handshake != nil {
		p.handshake.Stop()
	}
	if p.approved != nil {
		p.approval.Do(func() { close(p.approved) })
	}
}

// close releases the socket immediately and joins all peer-owned workers.
func (p *peer) close() {
	if p.handshake != nil {
		p.handshake.Stop()
	}
	p.stop()
	p.workers.Wait()
}

// stop interrupts both reader and writer without waiting on the current worker.
func (p *peer) stop() {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	p.once.Do(func() { close(p.done); _ = p.conn.Close() })
}

// writeJSON queues bounded encoded data; a slow peer never blocks routing.
func (p *peer) writeJSON(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	size := int64(len(data))
	if size > maxMessageBytes {
		return errors.New("transport frame too large")
	}
	if p.queued.Add(size) > p.byteLimit {
		p.queued.Add(-size)
		return errors.New("peer queue full")
	}
	if p.budget.Add(size) > serviceQueueBytes {
		p.budget.Add(-size)
		p.queued.Add(-size)
		return errors.New("transport queue full")
	}
	select {
	case <-p.done:
		p.release(size)
		return errors.New("peer closed")
	default:
	}
	select {
	case p.queue <- data:
		return nil
	default:
		p.release(size)
		return errors.New("peer queue full")
	}
}

// release returns reserved queue memory after writing or abandoning a frame.
func (p *peer) release(size int64) { p.queued.Add(-size); p.budget.Add(-size) }

// writeLoop is the sole data writer and drains reservations on shutdown.
func (p *peer) writeLoop() {
	defer func() {
		for {
			select {
			case data := <-p.queue:
				p.release(int64(len(data)))
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-p.done:
			return
		case data := <-p.queue:
			_ = p.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			err := p.conn.WriteMessage(websocket.TextMessage, data)
			p.release(int64(len(data)))
			if err != nil {
				p.stop()
				return
			}
		}
	}
}

// keepalive only uses concurrency-safe control writes; reader configuration is fixed.
func (p *peer) keepalive() {
	ticker := time.NewTicker(pongTimeout / 3)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case reason := <-p.rejections:
			_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason), time.Now().Add(time.Second))
			p.stop()
			return
		case <-ticker.C:
			if err := p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				p.stop()
				return
			}
		}
	}
}

// reject schedules a bounded close notification without delaying the routing loop.
func (p *peer) reject(reason string) {
	if reason == "" || len(reason) > 123 {
		reason = "controller rejected agent session"
	}
	select {
	case p.rejections <- reason:
	default:
		p.stop()
	}
}
