// File purpose: Verifies schedule validation and system-local transition evaluation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/protocol"
	"github.com/RealisLux/NeoDSE/internal/store"
)

// TestScheduledEventsAreQueryable verifies generated occurrences and scoped access through the API.
func TestScheduledEventsAreQueryable(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: "", "other": ""})
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.Local)
	server.now = func() time.Time { return now }
	job := store.Schedule{ID: agentID, AgentID: agentID, Days: []string{"monday"}, PowerOff: "18:00", Enabled: true}
	if err := server.store.UpsertSchedule(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	server.sendOverride = func(string, protocol.Frame) error { return nil }
	server.runSchedules(context.Background(), now)
	handler, administrator := testAPI(t, server)
	_, viewer, err := server.createServiceAccount(context.Background(), serviceAccountInput{Name: "unrelated viewer", Roles: []Role{RoleViewer}, Agents: []string{"other"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	eventID := "schedule-display-01-2026-08-31T18:00-off"
	for _, test := range []struct {
		name, identifier, token string
		status                  int
	}{
		{"scheduled event", eventID, administrator, http.StatusOK},
		{"scoped denial", eventID, viewer, http.StatusForbidden},
		{"missing event", "schedule-missing", administrator, http.StatusNotFound},
		{"oversized identifier", strings.Repeat("x", 129), administrator, http.StatusNotFound},
		{"invalid identifier", "event!invalid", administrator, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/events/"+test.identifier, nil)
			request.Header.Set("Authorization", "Bearer "+test.token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("event status=%d body=%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if test.status == http.StatusOK {
				var state eventStateResponse
				if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.EventID != eventID || len(state.Targets) != 1 || state.Targets[0] != agentID {
					t.Fatalf("scheduled event response=%#v error=%v", state, err)
				}
			}
		})
	}
}

// TestDueTransitionsCatchesPreviousDay verifies bounded catch-up across local midnight.
func TestDueTransitionsCatchesPreviousDay(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("system-test", -7*60*60)
	t.Cleanup(func() { time.Local = previous })
	now := time.Date(2026, 9, 1, 0, 0, 30, 0, time.Local)
	job := store.Schedule{ID: "display-01", Days: []string{"monday"}, PowerOff: "23:59", Enabled: true}
	for _, test := range []struct {
		name string
		job  store.Schedule
		now  time.Time
		want int
	}{
		{"previous weekday", job, now, 1},
		{"outside catch-up window", job, now.Add(time.Minute), 0},
		{"wrong weekday", store.Schedule{Days: []string{"tuesday"}, PowerOff: "23:59"}, now, 0},
		{"checkpointed occurrence", store.Schedule{Days: job.Days, PowerOff: job.PowerOff, LastOffOccurrence: "2026-08-31T23:59-off"}, now, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			transitions := dueTransitions(test.job, test.now)
			if len(transitions) != test.want {
				t.Fatalf("dueTransitions()=%#v, want %d", transitions, test.want)
			}
			if test.want == 1 && transitions[0].occurrence != "2026-08-31T23:59-off" {
				t.Fatalf("previous day's occurrence=%q", transitions[0].occurrence)
			}
		})
	}
}

// TestCreateScheduleReminderOverride persists the explicit banner preference.
func TestCreateScheduleReminderOverride(t *testing.T) {
	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	for _, test := range []struct {
		name string
		body string
		want bool
	}{
		{"enabled", `{"days":["monday"],"power_on":"08:00","power_off":"18:00","enabled":true,"reminder_enabled":true}`, true},
		{"disabled", `{"days":["monday"],"power_on":"08:00","power_off":"18:00","enabled":true,"reminder_enabled":false}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", bytes.NewBufferString(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			server.createSchedule(response, request, agentID)
			if response.Code != 200 {
				t.Fatalf("createSchedule() status=%d body=%s", response.Code, response.Body.String())
			}
			var got store.Schedule
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil || got.ReminderEnabled != test.want {
				t.Fatalf("createSchedule()=%#v error=%v, reminder_enabled want %t", got, err, test.want)
			}
		})
	}
}

// TestValidateScheduleDoesNotRequireTimezone verifies schedules contain only local clock fields.
func TestValidateScheduleDoesNotRequireTimezone(t *testing.T) {
	job := schedule{Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	if message := validateSchedule(job); message != "" {
		t.Fatalf("validateSchedule() = %q", message)
	}
}

// TestDueTransitionsUsesSystemTimezone verifies weekday and clock evaluation use time.Local.
func TestDueTransitionsUsesSystemTimezone(t *testing.T) {
	location := time.FixedZone("system-test", -7*60*60)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	job := store.Schedule{ID: "schedule-1", Days: []string{"sunday"}, PowerOn: "17:00", PowerOff: "18:00", Enabled: true}
	now := time.Date(2026, 8, 31, 0, 0, 30, 0, time.UTC)
	transitions := dueTransitions(job, now)
	if len(transitions) != 1 || transitions[0].kind != "on" || transitions[0].occurrence != "2026-08-30T17:00-on" {
		t.Fatalf("dueTransitions() = %#v", transitions)
	}
}

// TestDueTransitionsDoesNotReplayPastDayEvents verifies a schedule created or
// edited late in the day does not replay its already elapsed power operations.
func TestDueTransitionsDoesNotReplayPastDayEvents(t *testing.T) {
	location := time.FixedZone("system-test", 0)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	job := store.Schedule{ID: "schedule-1", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	now := time.Date(2026, 9, 14, 23, 5, 27, 0, location)
	if transitions := dueTransitions(job, now); len(transitions) != 0 {
		t.Fatalf("dueTransitions() replayed stale transitions: %#v", transitions)
	}
}

// TestUntilNextMinuteAlignsScheduler verifies the scheduler wakes on HH:MM:00.
func TestUntilNextMinuteAlignsScheduler(t *testing.T) {
	now := time.Date(2026, 9, 14, 8, 12, 34, 567000000, time.UTC)
	if got, want := untilNextMinute(now), 25*time.Second+433*time.Millisecond; got != want {
		t.Fatalf("untilNextMinute() = %s, want %s", got, want)
	}
}

// TestDueWarningUsesFiveMinuteWindowAndCheckpoint verifies warning eligibility.
func TestDueWarningUsesFiveMinuteWindowAndCheckpoint(t *testing.T) {
	location := time.FixedZone("system-test", -7*60*60)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	job := store.Schedule{ID: "schedule-1", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true}
	before := time.Date(2026, 8, 31, 17, 54, 59, 0, location)
	if _, ok := dueWarning(job, before); ok {
		t.Fatal("warning became due before its five-minute window")
	}
	warning, ok := dueWarning(job, before.Add(time.Second))
	if !ok || warning.minutes != 5 || !warning.when.Equal(time.Date(2026, 9, 1, 0, 55, 0, 0, time.UTC)) || !warning.expiresAt.Equal(warning.when.Add(time.Minute)) {
		t.Fatalf("dueWarning()=%#v due=%t", warning, ok)
	}
	job.LastWarningOccurrence = warning.occurrence
	if _, ok := dueWarning(job, before.Add(30*time.Second)); ok {
		t.Fatal("checkpointed warning became due again")
	}
	job.LastWarningOccurrence = warning.occurrence
	next, ok := dueWarning(job, before.Add(time.Minute+time.Second))
	if !ok || next.minutes != 4 || next.occurrence != "2026-08-31T18:00-warning-4" {
		t.Fatalf("decremented dueWarning()=%#v due=%t", next, ok)
	}
	if _, ok := dueWarning(job, before.Add(5*time.Minute+time.Second)); ok {
		t.Fatal("warning remained due after power-off")
	}
}

// TestDueWarningHandlesPreviousDayLeadTime verifies early power-off warnings cross midnight.
func TestDueWarningHandlesPreviousDayLeadTime(t *testing.T) {
	location := time.FixedZone("system-test", -7*60*60)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	job := store.Schedule{ID: "schedule-1", Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "00:03", Enabled: true}
	now := time.Date(2026, 8, 30, 23, 58, 0, 0, location)
	warning, ok := dueWarning(job, now)
	if !ok || warning.minutes != 5 || warning.occurrence != "2026-08-31T00:03-warning-5" {
		t.Fatalf("cross-midnight dueWarning()=%#v due=%t", warning, ok)
	}
}

// TestScheduledWarningUpdatesEveryMinute verifies all replacement banners use the existing command.
func TestScheduledWarningUpdatesEveryMinute(t *testing.T) {
	location := time.FixedZone("system-test", -7*60*60)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	job := store.Schedule{ID: agentID, AgentID: agentID, Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true, ReminderEnabled: true}
	if err := server.store.UpsertSchedule(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	var banners []instruction.Command
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type == "command" {
			var message protocol.Command
			if err := protocol.Decode(frame.Payload, &message); err != nil {
				t.Fatal(err)
			}
			banners = append(banners, message.Command)
		}
		return nil
	}
	start := time.Date(2026, 8, 31, 17, 55, 0, 0, location)
	for minute := range 5 {
		server.now = func() time.Time { return start.Add(time.Duration(minute) * time.Minute) }
		server.runSchedules(context.Background(), start.Add(time.Duration(minute)*time.Minute))
	}
	if len(banners) != 5 {
		t.Fatalf("scheduled banners=%#v", banners)
	}
	for index, banner := range banners {
		if want := scheduledWarningCommand(5 - index); banner != want {
			t.Fatalf("banner %d=%#v, want %#v", index, banner, want)
		}
	}
}

// TestScheduledWarningCanBeDisabled verifies power transitions do not require reminder banners.
func TestScheduledWarningCanBeDisabled(t *testing.T) {
	location := time.FixedZone("system-test", 0)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	job := store.Schedule{ID: agentID, AgentID: agentID, Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true, ReminderEnabled: false}
	if err := server.store.UpsertSchedule(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	server.runSchedules(context.Background(), time.Date(2026, 8, 31, 17, 55, 0, 0, location))
	if _, err := server.store.Event(context.Background(), "schedule-display-01-2026-08-31T18:00-warning-5"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled reminder created an event: %v", err)
	}
}

// TestScheduledWriteFailureRejectsOfflinePowerOff verifies independent best-effort delivery.
func TestScheduledWriteFailureRejectsOfflinePowerOff(t *testing.T) {
	location := time.FixedZone("system-test", -7*60*60)
	previous := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previous })

	const agentID = "display-01"
	server := testServerWithAgents(t, Config{}, map[string]string{agentID: ""})
	job := store.Schedule{ID: agentID, AgentID: agentID, Days: []string{"monday"}, PowerOn: "08:00", PowerOff: "18:00", Enabled: true, ReminderEnabled: true}
	if err := server.store.UpsertSchedule(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	var banner protocol.Command
	server.sendOverride = func(_ string, frame protocol.Frame) error {
		if frame.Type == "command" {
			if err := protocol.Decode(frame.Payload, &banner); err != nil {
				t.Fatal(err)
			}
			return errors.New("simulated banner delivery failure")
		}
		return nil
	}
	warningTime := time.Date(2026, 8, 31, 17, 55, 0, 0, location)
	server.now = func() time.Time { return warningTime }
	server.runSchedules(context.Background(), warningTime)
	if want := scheduledWarningCommand(5); banner.Command != want {
		t.Fatalf("scheduled banner=%#v, want %#v", banner.Command, want)
	}
	server.runSchedules(context.Background(), warningTime.Add(5*time.Minute))
	if server.sessionFor(agentID) != nil {
		t.Fatal("failed sequence retained session")
	}
	event, err := server.store.Event(context.Background(), "schedule-display-01-2026-08-31T18:00-off")
	if err != nil || len(event.Deliveries) != 1 || event.Deliveries[0].Status != "rejected" {
		t.Fatalf("offline scheduled action: %#v %v", event, err)
	}
}
