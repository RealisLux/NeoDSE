// File purpose: Converts typed HTTP action routes into durable desired-state changes or transient commands.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/store"
)

// handlePlaylist replaces or clears durable content without a hardware operation.
func (s *Server) handlePlaylist(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	content := instruction.ContentState{Mode: instruction.ContentDefault}
	if r.Method == http.MethodPut {
		var request playlistRequest
		if !decodeJSONBody(w, r, &request) {
			return
		}
		content = instruction.ContentState{Mode: instruction.ContentPlaylist, URLs: request.URLs, ProxyAllow: request.ProxyAllow, Interval: request.Interval, StartAt: request.StartAt}
		if err := content.Validate(); err != nil {
			message := "invalid playlist"
			if errors.Is(err, instruction.ErrSinglePageInterval) || errors.Is(err, instruction.ErrPlaylistInterval) {
				message = err.Error()
			}
			writeAPIError(w, http.StatusBadRequest, message)
			return
		}
	}
	s.dispatchDesiredChange(w, r, target, broadcast, store.DesiredChange{Content: &content})
}

// handlePlaylistReconciliation updates only playlist timing from SQLite authority.
func (s *Server) handlePlaylistReconciliation(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	var request syncRequest
	if !decodeJSONBody(w, r, &request) {
		return
	}
	startAtTime, err := parseLocalMinute(request.StartAt, time.Local)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "playlist start time is outside supported bounds")
		return
	}
	startAt := startAtTime.Unix()
	if startAt < 0 || startAt > instruction.MaxPlaylistStartAt {
		writeAPIError(w, http.StatusBadRequest, "playlist start time is outside supported bounds")
		return
	}
	s.dispatchDesiredChange(w, r, target, broadcast, store.DesiredChange{StartAt: &startAt})
}

// handleDisplay dispatches one transient HDMI-CEC display command.
func (s *Server) handleDisplay(w http.ResponseWriter, r *http.Request, target, value string, broadcast bool) {
	s.handleValueCommand(w, r, target, broadcast, instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayOperation(value)}))
}

// handleDisplayVolume validates and dispatches one absolute CEC audio level.
func (s *Server) handleDisplayVolume(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	var request displayVolumeRequest
	if !decodeJSONBody(w, r, &request) {
		return
	}
	if request.Level == nil || *request.Level > 100 {
		writeAPIError(w, http.StatusBadRequest, "volume level must be between 0 and 100")
		return
	}
	s.handleValueCommand(w, r, target, broadcast, instruction.NewCommand(instruction.DisplayVolumeCommand{Level: *request.Level}))
}

// handleValueCommand validates a path-derived command before durable dispatch.
func (s *Server) handleValueCommand(w http.ResponseWriter, r *http.Request, target string, broadcast bool, command instruction.Command) {
	if err := command.Validate(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid command")
		return
	}
	s.dispatchCommand(w, r, target, broadcast, command)
}

// handleSerial strictly decodes and validates a structured peripheral action.
func (s *Server) handleSerial(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	var request serialRequest
	if !decodeJSONBody(w, r, &request) {
		return
	}
	command := instruction.NewCommand(instruction.SerialCommand{Command: request.Command, State: request.State, PeriodMS: request.PeriodMS, RelayID: request.RelayID})
	if err := command.Validate(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid serial action")
		return
	}
	s.dispatchCommand(w, r, target, broadcast, command)
}

// handleBanner validates and dispatches one transient GTK overlay message.
func (s *Server) handleBanner(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	var request bannerRequest
	if !decodeJSONBody(w, r, &request) {
		return
	}
	command := instruction.NewCommand(instruction.BannerCommand{
		Message: instruction.BannerMessage(request.Message), Severity: instruction.BannerSeverity(request.Severity),
		DurationSeconds: instruction.BannerDuration(request.DurationSeconds),
	})
	if err := command.Validate(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid banner")
		return
	}
	s.dispatchCommand(w, r, target, broadcast, command)
}

// playlistRoute applies a playlist request to the agent identified by the route.
func (s *Server) playlistRoute(w http.ResponseWriter, r *http.Request) {
	s.handlePlaylist(w, r, r.PathValue("agentId"), false)
}

// playlistSyncRoute applies an explicit playlist start time to one agent.
func (s *Server) playlistSyncRoute(w http.ResponseWriter, r *http.Request) {
	s.handlePlaylistReconciliation(w, r, r.PathValue("agentId"), false)
}

// playlistReloadRoute reloads active playlist documents without replacing their WebKit views.
func (s *Server) playlistReloadRoute(w http.ResponseWriter, r *http.Request) {
	s.handleValueCommand(w, r, r.PathValue("agentId"), false, instruction.NewCommand(instruction.ReloadCommand{}))
}

// displayOperationRoute applies a validated CEC operation to one agent.
func (s *Server) displayOperationRoute(w http.ResponseWriter, r *http.Request) {
	s.handleDisplay(w, r, r.PathValue("agentId"), r.PathValue("operation"), false)
}

// displayVolumeRoute sets the absolute CEC audio level on one agent.
func (s *Server) displayVolumeRoute(w http.ResponseWriter, r *http.Request) {
	s.handleDisplayVolume(w, r, r.PathValue("agentId"), false)
}

// soundRoute dispatches one validated sound profile to an agent.
func (s *Server) soundRoute(w http.ResponseWriter, r *http.Request) {
	s.handleValueCommand(w, r, r.PathValue("agentId"), false, instruction.NewCommand(instruction.SoundCommand{Profile: instruction.SoundProfile(r.PathValue("profile"))}))
}

// serialRoute decodes and dispatches a structured serial action to one agent.
func (s *Server) serialRoute(w http.ResponseWriter, r *http.Request) {
	s.handleSerial(w, r, r.PathValue("agentId"), false)
}

// bannerRoute dispatches a transient overlay message to one agent.
func (s *Server) bannerRoute(w http.ResponseWriter, r *http.Request) {
	s.handleBanner(w, r, r.PathValue("agentId"), false)
}

// broadcastPlaylistRoute applies a playlist request to the caller's authorized agents.
func (s *Server) broadcastPlaylistRoute(w http.ResponseWriter, r *http.Request) {
	s.handlePlaylist(w, r, "*", true)
}

// broadcastPlaylistSyncRoute applies a shared playlist start time to authorized agents.
func (s *Server) broadcastPlaylistSyncRoute(w http.ResponseWriter, r *http.Request) {
	s.handlePlaylistReconciliation(w, r, "*", true)
}

// broadcastPlaylistReloadRoute reloads playlist documents on every authorized agent.
func (s *Server) broadcastPlaylistReloadRoute(w http.ResponseWriter, r *http.Request) {
	s.handleValueCommand(w, r, "*", true, instruction.NewCommand(instruction.ReloadCommand{}))
}

// broadcastDisplayOperationRoute applies one CEC operation to authorized agents.
func (s *Server) broadcastDisplayOperationRoute(w http.ResponseWriter, r *http.Request) {
	s.handleDisplay(w, r, "*", r.PathValue("operation"), true)
}

// broadcastDisplayVolumeRoute sets the absolute CEC audio level on authorized agents.
func (s *Server) broadcastDisplayVolumeRoute(w http.ResponseWriter, r *http.Request) {
	s.handleDisplayVolume(w, r, "*", true)
}

// broadcastSoundRoute dispatches a sound profile to authorized agents.
func (s *Server) broadcastSoundRoute(w http.ResponseWriter, r *http.Request) {
	s.handleValueCommand(w, r, "*", true, instruction.NewCommand(instruction.SoundCommand{Profile: instruction.SoundProfile(r.PathValue("profile"))}))
}

// broadcastSerialRoute dispatches a structured serial action to authorized agents.
func (s *Server) broadcastSerialRoute(w http.ResponseWriter, r *http.Request) {
	s.handleSerial(w, r, "*", true)
}

// broadcastBannerRoute dispatches one overlay message to all authorized agents.
func (s *Server) broadcastBannerRoute(w http.ResponseWriter, r *http.Request) {
	s.handleBanner(w, r, "*", true)
}

// agentSystemRoute dispatches an allowlisted system operation to one agent.
func (s *Server) agentSystemRoute(w http.ResponseWriter, r *http.Request) {
	s.dispatchSystemOperation(w, r, r.PathValue("agentId"), false)
}

// broadcastSystemRoute dispatches an allowlisted system operation to authorized agents.
func (s *Server) broadcastSystemRoute(w http.ResponseWriter, r *http.Request) {
	s.dispatchSystemOperation(w, r, "*", true)
}

// dispatchSystemOperation maps one allowlisted route operation to an agent command.
func (s *Server) dispatchSystemOperation(w http.ResponseWriter, r *http.Request, target string, broadcast bool) {
	commands := map[string]instruction.Command{
		"restart":  instruction.NewCommand(instruction.RestartCommand{}),
		"reboot":   instruction.NewCommand(instruction.RebootCommand{}),
		"shutdown": instruction.NewCommand(instruction.ShutdownCommand{}),
	}
	command, ok := commands[r.PathValue("operation")]
	if !ok {
		writeAPIError(w, http.StatusNotFound, "resource not found")
		return
	}
	s.handleValueCommand(w, r, target, broadcast, command)
}

// dispatchDesiredChange commits state and event metadata before attempting delivery.
func (s *Server) dispatchDesiredChange(w http.ResponseWriter, r *http.Request, target string, broadcast bool, change store.DesiredChange) {
	targets, ok := s.operationTargets(w, r, target, broadcast)
	if !ok {
		return
	}
	eventID, err := generateEventID()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not generate event identifier")
		return
	}
	records, err := s.store.UpdateDesiredStates(r.Context(), eventID, "http-api", targets, change, time.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAPIError(w, http.StatusConflict, "agent has no authoritative playlist")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "could not persist desired state")
		}
		return
	}
	// A timing-only change lets a running renderer keep its documents.
	apply := ""
	if change.StartAt != nil && change.Content == nil {
		apply = "playback"
	}
	// The whole operation is committed. Finish its bounded delivery attempts
	// even if the requesting client disconnects during an earlier target.
	for _, record := range records {
		_ = s.publishDesiredStateWithApply(record, eventID, apply)
	}
	writeQueuedEvent(w, eventID)
}

// dispatchCommand commits one expiring command before attempting delivery.
func (s *Server) dispatchCommand(w http.ResponseWriter, r *http.Request, target string, broadcast bool, command instruction.Command) {
	targets, ok := s.operationTargets(w, r, target, broadcast)
	if !ok {
		return
	}
	if !broadcast && s.sessionFor(target) == nil {
		writeAPIErrorCode(w, http.StatusConflict, "agent_offline", "agent offline")
		return
	}
	now := time.Now().UTC()
	eventID, err := generateEventID()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not generate event identifier")
		return
	}
	records, err := s.store.CreateCommand(r.Context(), eventID, "http-api", targets, command, now, now.Add(5*time.Minute))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not persist command")
		return
	}
	// Durable targets belong to the committed operation, so cancellation of
	// the HTTP response must not leave later targets unattempted.
	for _, record := range records {
		s.deliverCommand(record)
	}
	writeQueuedEvent(w, eventID)
}

// operationTargets resolves one agent or the caller's authorized broadcast set.
func (s *Server) operationTargets(w http.ResponseWriter, r *http.Request, target string, broadcast bool) ([]string, bool) {
	if !broadcast {
		return []string{target}, true
	}
	targets, err := s.authorizedBroadcastTargets(r)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return nil, false
	}
	if len(targets) == 0 {
		writeAPIError(w, http.StatusForbidden, "service account has no authorized targets")
		return nil, false
	}
	return targets, true
}

// decodeJSONBody enforces one strict, bounded application/json value.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeAPIError(w, http.StatusRequestEntityTooLarge, "request body exceeds 1 MiB")
		} else {
			writeAPIError(w, http.StatusBadRequest, "could not read request body")
		}
		return false
	}
	// JSON permits only these ASCII whitespace bytes around a value.
	body = bytes.TrimLeft(body, " \t\r\n")
	if len(body) == 0 || body[0] != '{' {
		writeAPIError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid json")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAPIError(w, http.StatusBadRequest, "request body must contain one JSON value")
		return false
	}
	return true
}
