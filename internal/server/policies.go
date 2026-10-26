// File purpose: Canonicalizes proxy targets and authorizes agent egress against SQLite policy.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/RealisLux/NeoDSE/internal/destination"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"github.com/RealisLux/NeoDSE/internal/proxyauth"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

// revokeProxyPolicy removes all current egress authority for one agent.
func (s *Server) revokeProxyPolicy(ctx context.Context, agentID string) (bool, error) {
	return s.store.RevokeProxyPolicy(ctx, agentID)
}

// generateEventID returns an unpredictable identifier safe for logs and URLs.
func generateEventID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "evt-" + hex.EncodeToString(random), nil
}

// agentPSKValue loads an agent secret only for protocol and proxy authentication.
func (s *Server) agentPSKValue(ctx context.Context, agentID string) (string, bool) {
	if s.store == nil {
		return "", false
	}
	value, err := s.store.AgentPSK(ctx, agentID)
	if err != nil {
		return "", false
	}
	return value, true
}

// proxyAuthorizeHandler authenticates the proxy and agent before exact SQLite policy lookup.
func (s *Server) proxyAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	internalToken, err := proxyauth.InternalToken(s.config.Server.ProxyInternalPSK)
	if err != nil || !hmac.Equal([]byte(r.Header.Get("X-NeoDSE-Proxy-Token")), []byte(internalToken)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaTypeErr != nil || mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var req wire.AuthorizeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body exceeds 64 KiB", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "request must contain one json value", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.Host == "" || req.Port == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Scheme != "http" && req.Scheme != "https" {
		http.Error(w, "invalid scheme", http.StatusBadRequest)
		return
	}
	session := s.authenticatedSession(r.Context(), req.AgentID)
	if session == nil || len(session.keys[keyderivation.ProxyClient]) != keyderivation.KeyBytes ||
		!hmac.Equal([]byte(req.Token), []byte(hex.EncodeToString(session.keys[keyderivation.ProxyClient]))) {
		writeJSON(w, http.StatusOK, wire.AuthorizeResponse{Authenticated: false})
		return
	}
	key, err := destination.Canonical(req.Scheme, req.Host, req.Port)
	if err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	allowed, err := s.store.ProxyAllowed(r.Context(), req.AgentID, key)
	if err != nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, wire.AuthorizeResponse{
		Authenticated: true,
		Allowed:       allowed,
	})
}
