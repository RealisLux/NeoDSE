// File purpose: Parses bounded proxy credentials and queries the controller authorization backend.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/wire"
)

var proxyTokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// proxyCredentials strictly parses bounded Basic credentials. The agent ID is
// only a claim until the controller authenticates it, so it is not logged.
func (p *Proxy) proxyCredentials(r *http.Request) (string, string, string) {
	value := r.Header.Get("Proxy-Authorization")
	if value == "" {
		return "", "", "header_missing"
	}
	if !strings.HasPrefix(strings.ToLower(value), "basic ") {
		return "", "", "unsupported_scheme"
	}
	encoded := strings.TrimSpace(value[len("basic "):])
	if len(encoded) > 256 {
		return "", "", "credential_too_large"
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", "invalid_base64"
	}
	agentID, token, ok := strings.Cut(string(decoded), ":")
	if !ok || !identity.ValidAgentID(agentID) || !proxyTokenPattern.MatchString(token) {
		return "", "", "invalid_basic_format"
	}
	p.debugLog("proxy authentication parsed")
	return agentID, token, ""
}

// authorize queries the controller with stream and service cancellation.
func (p *Proxy) authorize(ctx context.Context, requestID uint64, agentID, token, host, port, scheme string) authorizationDecision {
	request, err := p.newAuthorizationRequest(ctx, agentID, token, host, port, scheme)
	if err != nil {
		p.logAuthorizationUnavailable(requestID, "reason=invalid_request")
		return authorizationUnavailable
	}
	if p.backendClient == nil {
		return authorizationUnavailable
	}
	started := time.Now()
	response, err := p.backendClient.Do(request)
	if err != nil {
		// A client that disconnects or a lease that ends cancels its own lookup.
		if !errors.Is(ctx.Err(), context.Canceled) {
			p.logAuthorizationUnavailable(requestID, fmt.Sprintf("reason=backend_unreachable duration=%s", time.Since(started)))
		}
		return authorizationUnavailable
	}
	defer response.Body.Close()
	out, err := decodeAuthorizationResponse(response)
	if err != nil {
		p.logAuthorizationUnavailable(requestID, fmt.Sprintf("reason=invalid_response status=%d duration=%s", response.StatusCode, time.Since(started)))
		return authorizationUnavailable
	}
	if !out.Authenticated {
		return authorizationCredentialsRejected
	}
	if !out.Allowed {
		return authorizationDenied
	}
	return authorizationAllowed
}

// newAuthorizationRequest creates one bounded controller request with the internal credential.
func (p *Proxy) newAuthorizationRequest(ctx context.Context, agentID, token, host, port, scheme string) (*http.Request, error) {
	base := strings.TrimRight(p.config.Proxy.BackendURL, "/")
	if base == "" || p.internalToken == "" {
		return nil, errors.New("authorization backend is not configured")
	}
	payload := wire.AuthorizeRequest{AgentID: agentID, Token: token, Host: host, Port: port, Scheme: scheme}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/internal/v1/proxy/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-NeoDSE-Proxy-Token", p.internalToken)
	return request, nil
}

// decodeAuthorizationResponse strictly decodes one successful bounded backend response.
func decodeAuthorizationResponse(response *http.Response) (wire.AuthorizeResponse, error) {
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return wire.AuthorizeResponse{}, errors.New("authorization backend returned a non-success status")
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return wire.AuthorizeResponse{}, errors.New("authorization backend returned an invalid content type")
	}
	// Read one extra byte so a limit cannot disguise trailing data as EOF.
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return wire.AuthorizeResponse{}, err
	}
	if len(body) > 64<<10 {
		return wire.AuthorizeResponse{}, errors.New("authorization backend response exceeds 64 KiB")
	}
	var result wire.AuthorizeResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return wire.AuthorizeResponse{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return wire.AuthorizeResponse{}, errors.New("authorization backend returned multiple JSON values")
	}
	return result, nil
}
