// File purpose: Bounds subprocess output without exposing it in failure messages.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"bytes"
	"context"
	"sync"
)

const maxHelperOutput = 1 << 20

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
	cancel   context.CancelFunc
}

// Write stops the helper immediately when its combined output exceeds the bound.
func (output *boundedOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	available := maxHelperOutput - output.buffer.Len()
	if len(data) > available {
		output.overflow = true
		output.cancel()
	}
	_, _ = output.buffer.Write(data[:min(len(data), available)])
	return len(data), nil
}
