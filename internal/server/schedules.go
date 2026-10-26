// File purpose: Validates, stores, and evaluates recurring display schedules.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/store"
)

var clockPattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
var weekdays = map[string]time.Weekday{"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday}

type schedule = store.Schedule
type scheduleRequest struct {
	Days            []string `json:"days"`
	PowerOn         string   `json:"power_on"`
	PowerOff        string   `json:"power_off"`
	Enabled         bool     `json:"enabled"`
	ReminderEnabled *bool    `json:"reminder_enabled"`
}
type scheduledTransition struct {
	job                     store.Schedule
	kind, power, occurrence string
	when                    time.Time
}

type scheduledWarning struct {
	job        store.Schedule
	occurrence string
	minutes    int
	when       time.Time
	expiresAt  time.Time
}

// listSchedules returns all schedules owned by one agent.
func (s *Server) listSchedules(ctx context.Context, w http.ResponseWriter, agentID string) {
	out, err := s.store.Schedules(ctx, agentID)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// createSchedule validates and creates or replaces the one schedule owned by an agent.
func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request, agentID string) {
	var request scheduleRequest
	if !decodeJSONBody(w, r, &request) {
		return
	}
	if request.ReminderEnabled == nil {
		writeAPIError(w, http.StatusBadRequest, "reminder_enabled is required")
		return
	}
	v := schedule{Days: request.Days, PowerOn: request.PowerOn, PowerOff: request.PowerOff, Enabled: request.Enabled, ReminderEnabled: *request.ReminderEnabled}
	if err := validateSchedule(v); err != "" {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	v.ID = agentID
	v.Days = normalizeDays(v.Days)
	v.AgentID = agentID
	err := s.store.UpsertSchedule(r.Context(), v)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not create schedule")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// deleteSchedule removes one schedule owned by an agent.
func (s *Server) deleteSchedule(ctx context.Context, w http.ResponseWriter, agentID, id string) {
	err := s.store.DeleteSchedule(ctx, agentID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listSchedulesRoute returns schedules for the route's agent.
func (s *Server) listSchedulesRoute(w http.ResponseWriter, r *http.Request) {
	s.listSchedules(r.Context(), w, r.PathValue("agentId"))
}

// createScheduleRoute creates a schedule for the route's agent.
func (s *Server) createScheduleRoute(w http.ResponseWriter, r *http.Request) {
	s.createSchedule(w, r, r.PathValue("agentId"))
}

// deleteScheduleRoute removes the schedule owned by the route agent.
func (s *Server) deleteScheduleRoute(w http.ResponseWriter, r *http.Request) {
	s.deleteSchedule(r.Context(), w, r.PathValue("agentId"), r.PathValue("agentId"))
}

// validateSchedule returns a public validation message or an empty string.
func validateSchedule(v schedule) string {
	if !clockPattern.MatchString(v.PowerOn) || !clockPattern.MatchString(v.PowerOff) {
		return "power_on and power_off must use HH:MM"
	}
	if v.PowerOn == v.PowerOff {
		return "power_on and power_off must differ"
	}
	if len(v.Days) == 0 || len(v.Days) > 7 {
		return "days must contain one or more weekdays"
	}
	seen := map[string]bool{}
	for _, day := range v.Days {
		day = strings.ToLower(day)
		if _, ok := weekdays[day]; !ok {
			return fmt.Sprintf("invalid weekday %q", day)
		}
		if seen[day] {
			return "days contains a duplicate weekday"
		}
		seen[day] = true
	}
	return ""
}

// normalizeDays returns weekdays in deterministic calendar order.
func normalizeDays(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(v)
	}
	sort.Slice(out, func(i, j int) bool { return weekdays[out[i]] < weekdays[out[j]] })
	return out
}

// includesDay reports whether a schedule includes the requested weekday.
func includesDay(days []string, weekday time.Weekday) bool {
	for _, day := range days {
		if weekdays[strings.ToLower(day)] == weekday {
			return true
		}
	}
	return false
}

// parseLocalClock combines a validated HH:MM value with a local date.
func parseLocalClock(now time.Time, value string) (time.Time, error) {
	return parseLocalMinute(now.Format("2006-01-02")+"T"+value, now.Location())
}

// parseLocalMinute rejects times that timezone rules normalize into a different wall-clock minute.
func parseLocalMinute(value string, location *time.Location) (time.Time, error) {
	const layout = "2006-01-02T15:04"
	parsed, err := time.ParseInLocation(layout, value, location)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.Format(layout) != value {
		return time.Time{}, errors.New("local time does not exist in the controller timezone")
	}
	return parsed, nil
}
