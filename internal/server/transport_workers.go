// File purpose: Bounds connection-owned inbound workers and retires disconnected agent queues.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

const controllerMaxAgentWorkers = wire.MaxConnectedAgents

type agentFrameWorker struct {
	agentID, connectionID string
	queue                 chan routedFrame
	done                  chan struct{}
}

// agentFrameWorkers is owned by the transport reader. Retired workers retain
// their slot until their in-flight handler ends; a replacement for the same
// identity waits for its predecessor before processing any application frame.
type agentFrameWorkers struct {
	link        *controllerLink
	ctx         context.Context
	group       *sync.WaitGroup
	budget      *atomic.Int64
	active      map[string]*agentFrameWorker
	latest      map[string]*agentFrameWorker
	completed   chan *agentFrameWorker
	workerCount int
}

// newAgentFrameWorkers initializes reader-owned worker and memory accounting.
func newAgentFrameWorkers(ctx context.Context, link *controllerLink, group *sync.WaitGroup, budget *atomic.Int64) *agentFrameWorkers {
	return &agentFrameWorkers{
		link: link, ctx: ctx, group: group, budget: budget,
		active: make(map[string]*agentFrameWorker), latest: make(map[string]*agentFrameWorker),
		completed: make(chan *agentFrameWorker, controllerMaxAgentWorkers),
	}
}

// stop closes every remaining queue after the reader stops admitting frames.
func (workers *agentFrameWorkers) stop() {
	for agentID, worker := range workers.active {
		workers.retire(agentID, worker.connectionID)
	}
}

// reap releases only workers that finished, including any draining predecessors.
func (workers *agentFrameWorkers) reap() {
	for {
		select {
		case worker := <-workers.completed:
			workers.workerCount--
			if workers.latest[worker.agentID] == worker {
				delete(workers.latest, worker.agentID)
			}
		default:
			return
		}
	}
}

// retire immediately returns buffered byte reservations without waiting for an
// in-flight handler. A delayed disconnect cannot retire a replacement queue.
func (workers *agentFrameWorkers) retire(agentID, connectionID string) {
	worker := workers.active[agentID]
	if worker == nil || worker.connectionID != connectionID {
		return
	}
	delete(workers.active, agentID)
	close(worker.queue)
	for frame := range worker.queue {
		workers.budget.Add(-int64(len(frame.Payload)))
	}
}

// lifecycle applies the same connection ownership as the routing authority.
func (workers *agentFrameWorkers) lifecycle(frame routedFrame) {
	worker := workers.active[frame.AgentID]
	if worker == nil {
		return
	}
	if frame.Type == "disconnected" && worker.connectionID == frame.ConnectionID ||
		frame.Type == "connected" && worker.connectionID != frame.ConnectionID {
		workers.retire(worker.agentID, worker.connectionID)
	}
}

// enqueue admits bounded work without making the transport reader wait for a
// handler. Capacity errors belong to this route, never the whole controller.
func (workers *agentFrameWorkers) enqueue(frame routedFrame) error {
	workers.reap()
	worker := workers.active[frame.AgentID]
	if worker == nil {
		if workers.workerCount >= controllerMaxAgentWorkers {
			return errors.New("controller agent worker capacity reached")
		}
		worker = &agentFrameWorker{agentID: frame.AgentID, connectionID: frame.ConnectionID,
			queue: make(chan routedFrame, 32), done: make(chan struct{})}
		previous := workers.latest[frame.AgentID]
		workers.active[frame.AgentID] = worker
		workers.latest[frame.AgentID] = worker
		workers.workerCount++
		workers.group.Go(func() {
			defer func() {
				close(worker.done)
				workers.completed <- worker
			}()
			if previous != nil {
				select {
				case <-previous.done:
				case <-workers.ctx.Done():
				}
			}
			workers.link.processAgentFrames(workers.ctx, worker.queue, workers.budget)
		})
	}
	size := int64(len(frame.Payload))
	if workers.budget.Add(size) > 64<<20 {
		workers.budget.Add(-size)
		return errors.New("controller inbound byte capacity reached")
	}
	select {
	case worker.queue <- frame:
		return nil
	default:
		workers.budget.Add(-size)
		return errors.New("agent queue capacity reached")
	}
}
