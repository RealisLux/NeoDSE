// File purpose: Applies authenticated desired state and transient commands without retaining durable client state.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

// handleDesiredState authenticates one complete state and reports application failures to the controller.
func (a *Agent) handleDesiredState(message protocol.DesiredState) error {
	if !a.verifyDesiredState(message) {
		a.infof("! Rejected desired state id=%s", message.EventID)
		return errors.New("desired state authentication or validation failed")
	}
	a.rememberEvent(message.EventID)
	a.publishCommandReceipt(message.EventID, "received", "desired_state", "")
	if a.desiredStateAlreadyApplied(message.Generation, message.Revision) {
		a.verbosef("| Desired state already applied generation=%s revision=%d", message.Generation, message.Revision)
		if message.Apply != "playback" && message.State.Content.Mode == instruction.ContentPlaylist {
			// Pages may have failed while the connection was down.
			a.scheduleReconnectReload(message.Generation, message.Revision)
		}
		a.publishCommandReceipt(message.EventID, "accepted", "desired_state", "")
		return nil
	}
	// New content replaces every view, so an earlier deferred reload is obsolete.
	a.cancelReconnectReload()
	// Bind the applied marker to the renderer socket that accepted this state.
	socket, err := os.Stat(a.config.Agent.UISocket)
	if err == nil {
		if message.Apply == "playback" && a.canApplyPlayback(message.Generation, message.Revision) {
			err = a.sendUICommand(uiPlaybackRequest{Command: "playback", Interval: message.State.Content.Interval, StartAt: message.State.Content.StartAt})
		} else {
			err = a.applyDesiredState(message.State)
		}
	}
	if err != nil {
		a.infof("! Desired state failed event_id=%s error=%s", message.EventID, err)
		a.publishCommandReceipt(message.EventID, "failed", "desired_state", "state application failed")
		a.retryRenderer()
		return nil
	}
	a.sessionMu.Lock()
	a.desiredGeneration, a.desiredRevision = message.Generation, message.Revision
	a.desiredUISocket = socket
	a.rendererRetry = false
	a.sessionMu.Unlock()
	a.publishCommandReceipt(message.EventID, "accepted", "desired_state", "")
	return nil
}

// reconnectReloadSpread spreads the page reload that follows reconnect
// reconciliation. A controller restart reconnects every display at once; a
// random delay keeps the fleet from reloading every page at the same moment.
const reconnectReloadSpread = 15 * time.Second

// scheduleReconnectReload reloads the unchanged playlist after a random delay,
// unless newer content or a renderer replacement makes the reload obsolete.
func (a *Agent) scheduleReconnectReload(generation string, revision uint64) {
	delay := reconnectReloadDelay()
	if a.reloadDelay != nil {
		delay = a.reloadDelay()
	}
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.reloadTimer != nil {
		a.reloadTimer.Stop()
	}
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		// Serialize the complete IPC exchange with cancellation. Stop alone
		// cannot join a callback that already started; otherwise it could
		// reload newer content after handleDesiredState has replaced it.
		a.reloadMu.Lock()
		defer a.reloadMu.Unlock()
		if a.reloadTimer != timer {
			return
		}
		a.reloadTimer = nil
		if (a.ctx != nil && a.ctx.Err() != nil) || !a.desiredStateAlreadyApplied(generation, revision) {
			return
		}
		if err := a.sendUICommand(uiReloadRequest{Command: "reload"}); err != nil {
			a.infof("! Playlist reload after reconnection failed: %v", err)
			a.retryRenderer()
		}
	})
	a.reloadTimer = timer
}

// cancelReconnectReload drops pending work and joins a reload already in progress.
func (a *Agent) cancelReconnectReload() {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.reloadTimer != nil {
		a.reloadTimer.Stop()
		a.reloadTimer = nil
	}
}

// reconnectReloadDelay draws a uniform delay below reconnectReloadSpread.
func reconnectReloadDelay() time.Duration {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(value[:]) % uint64(reconnectReloadSpread))
}

// canApplyPlayback permits timing-only changes only on the successfully applied
// preceding revision; skipped content or a new generation needs full restoration.
func (a *Agent) canApplyPlayback(generation string, revision uint64) bool {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	return !a.rendererRetry && a.desiredGeneration == generation && a.desiredRevision != 0 &&
		revision > a.desiredRevision && revision-a.desiredRevision == 1 && a.rendererUnchangedLocked()
}

// desiredStateAlreadyApplied keeps reconnect reconciliation from rebuilding an
// unchanged renderer. The applied marker is volatile, so an agent process
// restart still restores the controller-owned state into a fresh UI.
func (a *Agent) desiredStateAlreadyApplied(generation string, revision uint64) bool {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	return a.desiredGeneration == generation && a.desiredRevision == revision && a.rendererUnchangedLocked()
}

// rendererUnchangedLocked checks the volatile socket identity while sessionMu is held.
func (a *Agent) rendererUnchangedLocked() bool {
	current, err := os.Stat(a.config.Agent.UISocket)
	return err == nil && sameRendererSocket(a.desiredUISocket, current)
}

// sameRendererSocket includes creation metadata because a removed Unix socket's
// device and inode can be reused immediately by its replacement.
func sameRendererSocket(previous, current os.FileInfo) bool {
	return previous != nil && current != nil && os.SameFile(previous, current) &&
		previous.ModTime().Equal(current.ModTime()) && previous.Mode() == current.Mode()
}

// retryRenderer lets failure receipts drain before the next heartbeat reconnects.
func (a *Agent) retryRenderer() {
	a.sessionMu.Lock()
	a.rendererRetry = true
	a.sessionMu.Unlock()
}

// reconcileRenderer reconnects when a restarted renderer has lost applied content.
func (a *Agent) reconcileRenderer() {
	a.rendererReconcileMu.Lock()
	defer a.rendererReconcileMu.Unlock()
	if time.Now().Before(a.rendererReconcileAfter) {
		return
	}
	// A headless host has no renderer to restore. Reconcile when its socket
	// returns instead of reconnecting the control session on every heartbeat.
	if _, err := os.Stat(a.config.Agent.UISocket); err != nil {
		return
	}
	a.sessionMu.Lock()
	changed := a.rendererRetry || (a.desiredUISocket != nil && !a.rendererUnchangedLocked())
	if changed {
		a.desiredGeneration, a.desiredRevision, a.desiredUISocket = "", 0, nil
		a.rendererRetry = false
	}
	a.sessionMu.Unlock()
	if changed {
		a.connectionMu.RLock()
		connection := a.connection
		a.connectionMu.RUnlock()
		if connection != nil {
			_ = connection.ws.Close()
		}
	}
}

// handleCommand authenticates one transient command and reports execution failures to the controller.
func (a *Agent) handleCommand(message protocol.Command) error {
	operation := string(message.Command.Type())
	switch a.verifyCommand(message) {
	case commandRejected:
		a.infof("! Rejected transient command id=%s", message.EventID)
		return errors.New("command authentication or validation failed")
	case commandExpired:
		// A late action is never executed, but it is authentic: report it and
		// keep the session instead of forcing reconnection and page reloads.
		a.infof("! Expired transient command id=%s command=%s", message.EventID, operation)
		a.publishCommandReceipt(message.EventID, "expired", operation, "command expired before execution")
		return nil
	}
	a.rememberEvent(message.EventID)
	a.publishCommandReceipt(message.EventID, "received", operation, "")
	if message.Command.Type() == instruction.CommandRestart {
		// Keep the control session open while the UI socket is replaced. The
		// heartbeat may reconcile only after the final receipt has been sent.
		a.rendererReconcileMu.Lock()
		defer func() {
			// The controller resends desired state after storing the final receipt.
			// Retain a bounded fallback reconnect if that reconciliation never arrives.
			a.rendererReconcileAfter = time.Now().Add(30 * time.Second)
			a.rendererReconcileMu.Unlock()
		}()
	}
	result, err := a.executeCommand(message.Command)
	if err != nil {
		a.infof("! Command failed event_id=%s command=%s error=%s", message.EventID, operation, err)
		a.publishCommandReceiptWithResult(message.EventID, "failed", operation, err.Error(), result.details, result.value)
		return nil
	}
	a.publishCommandReceiptWithResult(message.EventID, "completed", operation, "", result.details, result.value)
	return nil
}

// rememberEvent updates only volatile status information reported to the controller.
func (a *Agent) rememberEvent(eventID string) {
	a.stateMu.Lock()
	a.lastEventID = eventID
	a.stateMu.Unlock()
}

// applyDesiredState applies complete durable content without hardware side effects.
func (a *Agent) applyDesiredState(state instruction.DesiredState) error {
	return a.applyContentState(state.Content)
}

// applyContentState sends a complete content instruction independently of optional CEC support.
func (a *Agent) applyContentState(content instruction.ContentState) error {
	if a.contentRenderer != nil {
		return a.contentRenderer(content)
	}
	if content.Mode == instruction.ContentDefault {
		a.updateControlConnectionStatus()
		return a.sendUICommand(uiDefaultRequest{Command: "default"})
	}
	if err := a.prepareUIForRemoteContent(); err != nil {
		return err
	}
	return a.sendUICommand(uiPlaylistRequest{
		Command: "playlist", URLs: content.URLs,
		Interval: content.Interval, StartAt: content.StartAt,
	})
}

// commandResult carries bounded diagnostics and an optional normalized value.
type commandResult struct {
	details string
	value   string
}

// executeCommand maps one concrete command payload to its fixed operation.
func (a *Agent) executeCommand(command instruction.Command) (commandResult, error) {
	switch payload := command.Payload().(type) {
	case instruction.DisplayCommand:
		if payload.Operation == instruction.DisplayMute || payload.Operation == instruction.DisplayVolumeUp || payload.Operation == instruction.DisplayVolumeDown {
			details, err := a.controlAudio(string(payload.Operation))
			return commandResult{details: details}, err
		}
		if a.displayController != nil {
			return commandResult{}, a.displayController(payload.Operation)
		}
		details, err := a.controlDisplay(payload.Operation)
		value := "unknown"
		if err == nil {
			switch payload.Operation {
			case instruction.DisplayOn, instruction.DisplayActive:
				value = "on"
			case instruction.DisplayOff:
				value = "standby"
			}
		}
		a.rememberCECStatus(value, details)
		return commandResult{details: details, value: value}, err
	case instruction.DisplayVolumeCommand:
		details, err := a.controlAudioVolume(payload.Level)
		return commandResult{details: details, value: strconv.Itoa(int(payload.Level))}, err
	case instruction.SoundCommand:
		return commandResult{}, a.playSound(string(payload.Profile))
	case instruction.SerialCommand:
		details, err := a.writeSerial(payload)
		return commandResult{details: details}, err
	case instruction.BannerCommand:
		return commandResult{}, a.sendUICommand(uiBannerRequest{
			Command: "banner", Message: string(payload.Message),
			Severity: string(payload.Severity), DurationSeconds: int(payload.DurationSeconds),
		})
	case instruction.ReloadCommand:
		return commandResult{}, a.sendUICommand(uiReloadRequest{Command: "reload"})
	case instruction.RestartCommand:
		restartUI := a.restartUI
		if restartUI == nil {
			restartUI = restartRendererService
		}
		if err := restartUI(); err != nil {
			return commandResult{}, fmt.Errorf("restart UI service: %w", err)
		}
		return commandResult{}, nil
	case instruction.ShutdownCommand:
		return commandResult{}, runSystemCommand(instruction.CommandShutdown)
	case instruction.RebootCommand:
		return commandResult{}, runSystemCommand(instruction.CommandReboot)
	default:
		return commandResult{}, fmt.Errorf("unknown command payload %T", payload)
	}
}

// restartRendererService restarts the GTK process while the agent remains connected.
func restartRendererService() error {
	return runFixedSystemctl("restart", "neodse-ui.service")
}

// runFixedSystemctl executes only argument lists selected by in-process callers.
func runFixedSystemctl(arguments ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string{"/usr/bin/systemctl"}, arguments...)
	// #nosec G204 -- EXC-AGENT-SYSTEM-COMMAND: callers select only fixed argument lists.
	return exec.CommandContext(ctx, "/usr/bin/sudo", args...).Run()
}

// runSystemCommand permits only fixed host power operations through the fixed sudo path.
func runSystemCommand(action instruction.CommandType) error {
	var arguments []string
	switch action {
	case instruction.CommandShutdown:
		arguments = []string{"poweroff"}
	case instruction.CommandReboot:
		arguments = []string{"reboot"}
	default:
		return errors.New("system command is not permitted")
	}
	return runFixedSystemctl(arguments...)
}
