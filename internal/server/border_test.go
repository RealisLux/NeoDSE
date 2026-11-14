// File purpose: Verifies screen-border dispatch, input validation, role and agent scope checks.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
)

func TestBorderRoutes(t *testing.T) {
	s := testServerWithAgents(t, Config{}, map[string]string{"display-01": "", "display-02": ""})
	handler, admin := testAPI(t, s)
	var delivered []instruction.Command
	s.sendOverride = func(agentID string, frame protocol.Frame) error {
		if agentID != "display-01" || frame.Type != "command" {
			t.Fatalf("unexpected delivery %s %s", agentID, frame.Type)
		}
		var command protocol.Command
		if err := protocol.Decode(frame.Payload, &command); err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, command.Command)
		return nil
	}
	_, operator, err := s.createServiceAccount(context.Background(), serviceAccountInput{
		Name: "alerts", Roles: []Role{RoleAlertOperator}, Agents: []string{"display-01"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, viewer, err := s.createServiceAccount(context.Background(), serviceAccountInput{
		Name: "viewer", Roles: []Role{RoleViewer}, AllAgents: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method, target, body, token string
		status                      int
		want                        *instruction.BorderCommand
	}{
		{http.MethodPost, "display-01", `{"severity":"warning","duration_seconds":30}`, operator, 202, &instruction.BorderCommand{Severity: "warning", DurationSeconds: 30}},
		{http.MethodPost, "broadcast", `{"severity":"critical","duration_seconds":300}`, operator, 202, &instruction.BorderCommand{Severity: "critical", DurationSeconds: 300}},
		{http.MethodPost, "display-01", `{}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"info","duration_seconds":0}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"warning","duration_seconds":301}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"error","duration_seconds":10}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"info","duration_seconds":10,"color":"red"}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"info","duration_seconds":1.5}`, admin, 400, nil},
		{http.MethodPost, "display-01", `{"severity":"info","duration_seconds":10}`, viewer, 403, nil},
		{http.MethodPost, "display-02", `{"severity":"info","duration_seconds":10}`, operator, 403, nil},
		{http.MethodPost, "display-01", `{"severity":"info","duration_seconds":10}`, "", 401, nil},
		{http.MethodDelete, "display-01", "", admin, 405, nil},
		{http.MethodDelete, "broadcast", "", admin, 405, nil},
	} {
		before := len(delivered)
		request := httptest.NewRequest(test.method, "/api/v1/agents/"+test.target+"/border", strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer "+test.token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s body=%s: status=%d response=%s", test.method, test.target, test.body, response.Code, response.Body.String())
		}
		if test.want == nil {
			if len(delivered) != before {
				t.Fatal("rejected request reached renderer")
			}
		} else if len(delivered) != before+1 || delivered[before] != instruction.NewCommand(*test.want) {
			t.Fatalf("unexpected delivered commands: %#v", delivered)
		}
	}
	// An attempted send failure is recorded as uncertain rather than retried.
	s.sendOverride = func(string, protocol.Frame) error { return errors.New("fixture transport failure") }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agents/display-01/border", strings.NewReader(`{"severity":"warning","duration_seconds":30}`))
	request.Header.Set("Authorization", "Bearer "+operator)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), "event_id") {
		t.Fatalf("transport failure response: %d %s", response.Code, response.Body.String())
	}
	s.clearSessions()
	request.Body = io.NopCloser(strings.NewReader(`{"severity":"warning","duration_seconds":30}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("offline border status=%d response=%s", response.Code, response.Body.String())
	}
}
