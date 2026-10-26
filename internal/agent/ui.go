// File purpose: Sends bounded typed requests to the local renderer.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const uiCommandResponseTimeout = 20 * time.Second

// sendUICommand sends one typed UI request and requires an affirmative response.
func (a *Agent) sendUICommand(payload any) error {
	response, err := a.sendUIRequest(payload)
	if err != nil {
		return err
	}
	if response.Status != "accepted" {
		if response.Error == "" {
			response.Error = "command rejected"
		}
		return fmt.Errorf("UI acknowledgement: %s", response.Error)
	}
	return nil
}

// uiResponse is the bounded response envelope returned by the local UI process.
type uiResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

// uiDefaultRequest asks the local UI to restore its default content.
type uiDefaultRequest struct {
	Command string `json:"cmd"`
}

// uiReloadRequest asks the local UI to reload its current content.
type uiReloadRequest struct {
	Command string `json:"cmd"`
}

// uiPlaybackRequest updates playlist timing without reloading its documents.
type uiPlaybackRequest struct {
	Command  string `json:"cmd"`
	Interval int    `json:"interval,omitempty"`
	StartAt  int64  `json:"start_at"`
}

// uiPlaylistRequest supplies one validated playlist to the local UI.
type uiPlaylistRequest struct {
	Command  string   `json:"cmd"`
	URLs     []string `json:"urls"`
	Interval int      `json:"interval,omitempty"`
	StartAt  int64    `json:"start_at,omitempty"`
}

// uiBannerRequest supplies one validated transient overlay to the local UI.
type uiBannerRequest struct {
	Command         string `json:"cmd"`
	Message         string `json:"message"`
	Severity        string `json:"severity"`
	DurationSeconds int    `json:"duration_seconds"`
}

// uiStatusRequest supplies the local connectivity status rendered by the UI.
type uiStatusRequest struct {
	Command      string `json:"cmd"`
	AgentName    string `json:"agent_name"`
	FriendlyName string `json:"friendly_name,omitempty"`
	AgentIP      string `json:"agent_ip"`
	TunnelIP     string `json:"tunnel_ip"`
	Stage        string `json:"stage"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
}

// uiProxyAuthRequest replaces the session-bound proxy credential held by WebKit.
type uiProxyAuthRequest struct {
	Command string `json:"cmd"`
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

// uiProxyConfigRequest supplies the loopback proxy relay URL to WebKit.
type uiProxyConfigRequest struct {
	Command string `json:"cmd"`
	URL     string `json:"url"`
}

// sendUIRequest performs one bounded request-response exchange over local Unix IPC.
func (a *Agent) sendUIRequest(payload any) (uiResponse, error) {
	var response uiResponse
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := 2 * time.Second
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", a.config.Agent.UISocket)
	if err != nil {
		return response, err
	}
	defer conn.Close()
	// Shutdown must interrupt an unresponsive renderer instead of waiting for
	// its application acknowledgement deadline while Run joins its workers.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	data, err := json.Marshal(payload)
	if err != nil {
		return response, err
	}
	if len(data)+1 > 1<<20 {
		return response, errors.New("UI request exceeds 1 MiB")
	}
	data = append(data, '\n')

	// A renderer that stops reading must not block the agent indefinitely.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		if err != nil {
			return response, err
		}
		total += n
	}

	if unixConn, ok := conn.(*net.UnixConn); ok {
		if err := unixConn.CloseWrite(); err != nil {
			return response, err
		}
	}

	// Playlist acknowledgement can wait for proxy readiness and GTK application.
	if err := conn.SetReadDeadline(time.Now().Add(uiCommandResponseTimeout)); err != nil {
		return response, err
	}

	response, err = decodeUIResponse(conn, 4096)
	if err != nil {
		return response, fmt.Errorf("UI response: %w", err)
	}

	return response, nil
}

// decodeUIResponse strictly decodes one bounded UI response value.
func decodeUIResponse(reader io.Reader, maxBytes int64) (uiResponse, error) {
	var response uiResponse
	if maxBytes <= 0 {
		return response, errors.New("invalid response size limit")
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return response, err
	}
	if int64(len(data)) > maxBytes {
		return response, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return response, errors.New("response must contain one JSON value")
	}
	return response, nil
}
