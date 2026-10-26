// File purpose: Verifies local-time commands cannot silently move across a daylight-saving gap.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/store"
)

// TestScheduleClockRejectsNonexistentLocalTime keeps a DST gap from triggering power at a different clock time.
func TestScheduleClockRejectsNonexistentLocalTime(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, time.March, 29, 12, 0, 0, 0, location)
	if value, err := parseLocalClock(day, "02:30"); err == nil {
		t.Fatalf("nonexistent 02:30 normalized to %s", value)
	}
	for _, clock := range []string{"01:30", "03:30"} {
		value, err := parseLocalClock(day, clock)
		if err != nil || value.Format("15:04") != clock {
			t.Fatalf("valid %s parsed as %s: %v", clock, value, err)
		}
	}
}

// TestDueTransitionsSkipsDaylightGap verifies the public scheduling behavior, including a valid neighboring occurrence.
func TestDueTransitionsSkipsDaylightGap(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	original := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = original })
	now := time.Date(2026, time.March, 29, 3, 31, 0, 0, location)
	job := store.Schedule{ID: "display", Days: []string{"sunday"}, PowerOn: "02:30", PowerOff: "03:30", Enabled: true}
	transitions := dueTransitions(job, now)
	if len(transitions) != 1 || transitions[0].kind != "off" || transitions[0].occurrence != "2026-03-29T03:30-off" {
		t.Fatalf("gap should be skipped and valid neighboring time retained: %#v", transitions)
	}
}

// TestPlaylistSyncRejectsNonexistentLocalTime returns a validation error before changing durable content.
func TestPlaylistSyncRejectsNonexistentLocalTime(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	original := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = original })
	s := testServerWithAgents(t, Config{}, map[string]string{"display": ""})
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"start_at":"2026-03-29T02:30"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handlePlaylistReconciliation(w, r, "display", false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("nonexistent local time returned %d: %s", w.Code, w.Body.String())
	}
}
