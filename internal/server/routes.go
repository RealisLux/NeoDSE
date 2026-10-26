// File purpose: Declares every operational API route with its method, authorization, scope, and handler.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"net/http"
	"sort"

	"github.com/RealisLux/NeoDSE/internal/identity"
)

// apiRoute describes the security and dispatch policy for one HTTP method.
type apiRoute struct {
	capability  capability
	broadcast   bool
	agentScoped bool
	handler     http.HandlerFunc
}

// registerAPIRoutes installs the complete authenticated API surface.
func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	s.registerAPIPath(mux, "/api/v1/session", map[string]apiRoute{
		http.MethodGet: {capability: capView, handler: s.sessionRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents", map[string]apiRoute{
		http.MethodGet: {capability: capView, handler: s.listAgents},
	})
	agentMux := http.NewServeMux()
	broadcastMux := http.NewServeMux()
	mux.Handle("/api/v1/agents/broadcast/", broadcastMux)
	mux.Handle("/api/v1/agents/", agentMux)
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}", map[string]apiRoute{
		http.MethodGet: {capability: capView, agentScoped: true, handler: s.getAgentRoute},
	})
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}/state", map[string]apiRoute{
		http.MethodGet: {capability: capView, agentScoped: true, handler: s.getAgentStateRoute},
	})
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}/{operation}", map[string]apiRoute{
		http.MethodPost: {capability: capSystem, agentScoped: true, handler: s.agentSystemRoute},
	})
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}/proxy/revoke", map[string]apiRoute{
		http.MethodPost: {capability: capContent, agentScoped: true, handler: s.revokeWebRoute},
	})
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}/display/status", map[string]apiRoute{
		http.MethodGet: {capability: capView, agentScoped: true, handler: s.getDisplayStatusRoute},
	})
	s.registerAPIPath(agentMux, "/api/v1/agents/{agentId}/display/stream", map[string]apiRoute{
		http.MethodGet: {capability: capView, agentScoped: true, handler: s.displayStreamRoute},
	})
	s.registerAgentContentRoutes(agentMux)
	s.registerBroadcastRoutes(broadcastMux)
	s.registerScheduleRoutes(agentMux)
	s.registerAPIPath(mux, "/api/v1/events/{eventId}", map[string]apiRoute{
		http.MethodGet: {capability: capView, handler: s.eventStateHandler},
	})
	s.registerAPIPath(mux, "/api/v1/system/status", map[string]apiRoute{
		http.MethodGet: {capability: capView, handler: s.systemStatusHandler},
	})
	s.registerAccountRoutes(mux)
}

// registerAgentContentRoutes installs state and command routes for one agent.
func (s *Server) registerAgentContentRoutes(mux *http.ServeMux) {
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/playlist", map[string]apiRoute{
		http.MethodPut:    {capability: capContent, agentScoped: true, handler: s.playlistRoute},
		http.MethodDelete: {capability: capContent, agentScoped: true, handler: s.playlistRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/playlist/sync", map[string]apiRoute{
		http.MethodPost: {capability: capContent, agentScoped: true, handler: s.playlistSyncRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/playlist/reload", map[string]apiRoute{
		http.MethodPost: {capability: capContent, agentScoped: true, handler: s.playlistReloadRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/display/volume", map[string]apiRoute{
		http.MethodPost: {capability: capCEC, agentScoped: true, handler: s.displayVolumeRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/display/{operation}", map[string]apiRoute{
		http.MethodPost: {capability: capCEC, agentScoped: true, handler: s.displayOperationRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/sound/{profile}", map[string]apiRoute{
		http.MethodPost: {capability: capAlertIO, agentScoped: true, handler: s.soundRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/serial", map[string]apiRoute{
		http.MethodPost: {capability: capAlertIO, agentScoped: true, handler: s.serialRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/banner", map[string]apiRoute{
		http.MethodPost: {capability: capContent, agentScoped: true, handler: s.bannerRoute},
	})
}

// registerBroadcastRoutes installs operations whose target set is derived from account scope.
func (s *Server) registerBroadcastRoutes(mux *http.ServeMux) {
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/playlist", map[string]apiRoute{
		http.MethodPut:    {capability: capContent, broadcast: true, handler: s.broadcastPlaylistRoute},
		http.MethodDelete: {capability: capContent, broadcast: true, handler: s.broadcastPlaylistRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/playlist/sync", map[string]apiRoute{
		http.MethodPost: {capability: capContent, broadcast: true, handler: s.broadcastPlaylistSyncRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/playlist/reload", map[string]apiRoute{
		http.MethodPost: {capability: capContent, broadcast: true, handler: s.broadcastPlaylistReloadRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/display/volume", map[string]apiRoute{
		http.MethodPost: {capability: capCEC, broadcast: true, handler: s.broadcastDisplayVolumeRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/display/{operation}", map[string]apiRoute{
		http.MethodPost: {capability: capCEC, broadcast: true, handler: s.broadcastDisplayOperationRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/sound/{profile}", map[string]apiRoute{
		http.MethodPost: {capability: capAlertIO, broadcast: true, handler: s.broadcastSoundRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/serial", map[string]apiRoute{
		http.MethodPost: {capability: capAlertIO, broadcast: true, handler: s.broadcastSerialRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/banner", map[string]apiRoute{
		http.MethodPost: {capability: capContent, broadcast: true, handler: s.broadcastBannerRoute},
	})
	s.registerAPIPath(mux, "/api/v1/agents/broadcast/{operation}", map[string]apiRoute{
		http.MethodPost: {capability: capSystem, broadcast: true, handler: s.broadcastSystemRoute},
	})
}

// registerScheduleRoutes installs one schedule resource for each agent.
func (s *Server) registerScheduleRoutes(mux *http.ServeMux) {
	s.registerAPIPath(mux, "/api/v1/agents/{agentId}/schedules", map[string]apiRoute{
		http.MethodGet:    {capability: capView, agentScoped: true, handler: s.listSchedulesRoute},
		http.MethodPost:   {capability: capAccounts, agentScoped: true, handler: s.createScheduleRoute},
		http.MethodDelete: {capability: capAccounts, agentScoped: true, handler: s.deleteScheduleRoute},
	})
}

// registerAccountRoutes installs administrator-only service-account routes.
func (s *Server) registerAccountRoutes(mux *http.ServeMux) {
	s.registerAPIPath(mux, "/api/v1/service-accounts", map[string]apiRoute{
		http.MethodGet:  {capability: capAccounts, handler: s.listAccountsRoute},
		http.MethodPost: {capability: capAccounts, handler: s.createAccountRoute},
	})
	s.registerAPIPath(mux, "/api/v1/service-accounts/{accountId}", map[string]apiRoute{
		http.MethodGet:    {capability: capAccounts, handler: s.getAccountRoute},
		http.MethodPut:    {capability: capAccounts, handler: s.replaceAccountRoute},
		http.MethodDelete: {capability: capAccounts, handler: s.deleteAccountRoute},
	})
	s.registerAPIPath(mux, "/api/v1/service-accounts/{accountId}/rotate-token", map[string]apiRoute{
		http.MethodPost: {capability: capAccounts, handler: s.rotateAccountRoute},
	})
}

// registerAPIPath centralizes authentication, authorization, method handling, and agent existence checks.
func (s *Server) registerAPIPath(mux *http.ServeMux, pattern string, methods map[string]apiRoute) {
	mux.HandleFunc(pattern, s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		route, exists := methods[r.Method]
		if !exists {
			allowed := make([]string, 0, len(methods))
			for method := range methods {
				allowed = append(allowed, method)
			}
			sort.Strings(allowed)
			writeMethodNotAllowed(w, allowed...)
			return
		}
		agentID := r.PathValue("agentId")
		if route.agentScoped && !identity.ValidAgentID(agentID) {
			writeAPIError(w, http.StatusNotFound, "agent not found")
			return
		}
		if !requireCapability(w, r, route.capability, agentID, route.broadcast) {
			return
		}
		if route.agentScoped {
			exists, err := s.store.AgentExists(r.Context(), agentID)
			if err != nil {
				writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
				return
			}
			if !exists {
				writeAPIError(w, http.StatusNotFound, "agent not found")
				return
			}
		}
		route.handler(w, r)
	}))
}
