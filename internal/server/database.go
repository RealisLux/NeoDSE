// File purpose: Connects controller background reconciliation, scheduling, and retention work to the concrete store.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
	"github.com/RealisLux/NeoDSE/internal/store"
)

const scheduledWarningLead = 5 * time.Minute

// scheduledWarningCommand builds one minute-granularity replacement banner.
func scheduledWarningCommand(minutes int) instruction.Command {
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	return instruction.NewCommand(instruction.BannerCommand{
		Message:  instruction.BannerMessage(fmt.Sprintf("Screen will turn off in %d %s", minutes, unit)),
		Severity: instruction.BannerWarning, DurationSeconds: 60,
	})
}

// openDatabase opens the sole durable authority configured for the controller with its decrypted key.
func (s *Server) openDatabase(key []byte) error {
	database, err := store.Open(context.Background(), s.config.Server.Database, key)
	if err != nil {
		return err
	}
	s.store = database
	return nil
}

// sendDesiredState persists a reconciliation event before sending complete authoritative state.
func (s *Server) sendDesiredState(agentID string) error {
	if s.store == nil {
		return errors.New("authority store is unavailable")
	}
	storeContext, cancel := boundedStoreContext()
	defer cancel()
	eventID, err := generateEventID()
	if err != nil {
		return err
	}
	record, err := s.store.CreateStateEvent(storeContext, eventID, "reconciliation", agentID, time.Now().UTC())
	if err != nil {
		return err
	}
	return s.publishDesiredState(record, eventID)
}

// runScheduler catches up once, then evaluates schedules on whole-minute boundaries.
func (s *Server) runScheduler(ctx context.Context) {
	s.runSchedules(ctx, time.Now())
	timer := time.NewTimer(untilNextMinute(time.Now()))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			s.runSchedules(ctx, now)
			timer.Reset(untilNextMinute(time.Now()))
		}
	}
}

// untilNextMinute returns the delay to the next local wall-clock minute.
func untilNextMinute(now time.Time) time.Duration {
	return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

// runRetention performs bounded cleanup immediately and then hourly.
func (s *Server) runRetention(ctx context.Context) {
	s.cleanupRetention(ctx, time.Now().UTC())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.cleanupRetention(ctx, now.UTC())
		}
	}
}

// cleanupRetention delegates batched cleanup using configured periods.
func (s *Server) cleanupRetention(ctx context.Context, now time.Time) {
	retention := store.Retention{
		Events: time.Duration(s.config.Server.EventRetentionDays) * 24 * time.Hour,
	}
	if err := s.store.Cleanup(ctx, now, retention); err != nil {
		log.Printf("! Retention cleanup failed: %v", err)
	}
}

// runSchedules derives due transitions from durable jobs and applies them in time order.
func (s *Server) runSchedules(ctx context.Context, now time.Time) {
	jobs, err := s.store.EnabledSchedules(ctx)
	if err != nil {
		log.Printf("! Schedule query failed: %v", err)
		return
	}
	var transitions []scheduledTransition
	var warnings []scheduledWarning
	warningJobs := make(map[string]struct{})
	for _, job := range jobs {
		transitions = append(transitions, dueTransitions(job, now)...)
		if warning, ok := dueWarning(job, now); job.ReminderEnabled && ok {
			warnings = append(warnings, warning)
			warningJobs[warning.job.ID] = struct{}{}
		}
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].when.Before(warnings[j].when) })
	sort.Slice(transitions, func(i, j int) bool { return transitions[i].when.Before(transitions[j].when) })
	for _, warning := range warnings {
		s.executeScheduledWarning(ctx, warning, now.UTC())
	}
	for _, transition := range transitions {
		// Do not revive a display while its imminent power-off warning is active.
		if transition.kind == "on" {
			if _, warningActive := warningJobs[transition.job.ID]; warningActive {
				continue
			}
		}
		s.executeScheduledTransition(ctx, transition, now.UTC())
	}
}

// dueWarning returns the uncheckpointed one-minute delivery window before power-off.
func dueWarning(job store.Schedule, now time.Time) (scheduledWarning, bool) {
	local := now.In(time.Local)
	for dayOffset := 0; dayOffset <= 1; dayOffset++ {
		offDay := local.AddDate(0, 0, dayOffset)
		if !includesDay(job.Days, offDay.Weekday()) {
			continue
		}
		off, err := parseLocalClock(offDay, job.PowerOff)
		if err != nil {
			return scheduledWarning{}, false
		}
		remaining := off.Sub(local)
		if remaining <= 0 || remaining > scheduledWarningLead {
			continue
		}
		minutes := int((remaining + time.Minute - 1) / time.Minute)
		when := off.Add(-time.Duration(minutes) * time.Minute)
		expiresAt := off.Add(-time.Duration(minutes-1) * time.Minute)
		occurrence := fmt.Sprintf("%s-warning-%d", off.Format("2006-01-02T15:04"), minutes)
		if occurrence != job.LastWarningOccurrence {
			return scheduledWarning{job: job, occurrence: occurrence, minutes: minutes, when: when.UTC(), expiresAt: expiresAt.UTC()}, true
		}
	}
	return scheduledWarning{}, false
}

// executeScheduledWarning queues the banner before attempting best-effort delivery.
func (s *Server) executeScheduledWarning(ctx context.Context, warning scheduledWarning, now time.Time) {
	eventID := "schedule-" + warning.job.ID + "-" + warning.occurrence
	record, err := s.store.ApplyScheduledWarning(ctx, warning.job, warning.occurrence, eventID, scheduledWarningCommand(warning.minutes), now, warning.expiresAt)
	if errors.Is(err, store.ErrConflict) {
		return
	}
	if err != nil {
		log.Printf("! Scheduled warning failed agent=%s schedule_id=%s", warning.job.AgentID, warning.job.ID)
		return
	}
	s.deliverCommand(record)
}

const scheduledTransitionWindow = 2 * time.Minute

// dueTransitions returns recent schedule occurrences that are due and not checkpointed.
func dueTransitions(job store.Schedule, now time.Time) []scheduledTransition {
	local := now.In(time.Local)
	var transitions []scheduledTransition
	items := []struct{ kind, power, value, last string }{
		{"on", "on", job.PowerOn, job.LastOnOccurrence},
		{"off", "off", job.PowerOff, job.LastOffOccurrence},
	}
	// A delayed tick or restart just after midnight can still owe yesterday's
	// transition. Apply the weekday to the occurrence, not the current date.
	for dayOffset := -1; dayOffset <= 0; dayOffset++ {
		day := local.AddDate(0, 0, dayOffset)
		if !includesDay(job.Days, day.Weekday()) {
			continue
		}
		for _, item := range items {
			when, err := parseLocalClock(day, item.value)
			if item.value == "" || err != nil || when.After(local) || local.Sub(when) > scheduledTransitionWindow {
				continue
			}
			occurrence := when.Format("2006-01-02T15:04") + "-" + item.kind
			if occurrence != item.last {
				transitions = append(transitions, scheduledTransition{job: job, kind: item.kind, power: item.power, occurrence: occurrence, when: when.UTC()})
			}
		}
	}
	return transitions
}

// executeScheduledTransition checkpoints and queues a transient CEC command before delivery.
func (s *Server) executeScheduledTransition(ctx context.Context, transition scheduledTransition, now time.Time) {
	eventID := "schedule-" + transition.job.ID + "-" + transition.occurrence
	record, err := s.store.ApplyScheduledDisplay(ctx, transition.job, transition.kind, transition.occurrence, eventID, instruction.DisplayOperation(transition.power), now)
	if errors.Is(err, store.ErrConflict) {
		return
	}
	if err != nil {
		log.Printf("! Scheduled transition failed agent=%s schedule_id=%s error=%v", transition.job.AgentID, transition.job.ID, err)
		return
	}
	s.deliverCommand(record)
}
