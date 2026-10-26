// File purpose: Defines durable content state and validated proxy targets shared by controllers and agents.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package instruction owns the validated operations that a NeoDSE controller
// may ask a display agent to apply. It deliberately contains no transport,
// persistence, or operating-system behavior.
package instruction

import (
	"errors"
	"fmt"
	"sort"

	"github.com/RealisLux/NeoDSE/internal/destination"
)

// DisplayOperation describes one HDMI-CEC display or audio operation.
type DisplayOperation string

const (
	DisplayOn         DisplayOperation = "on"
	DisplayOff        DisplayOperation = "off"
	DisplayActive     DisplayOperation = "active"
	DisplayMute       DisplayOperation = "mute"
	DisplayVolumeUp   DisplayOperation = "volup"
	DisplayVolumeDown DisplayOperation = "voldown"
)

// Playlist bounds shared by the API, storage, agent and renderer. Every page
// stays loaded for instant rotation, so the page count bounds renderer memory
// and the proxy connections one display holds.
const (
	MaxPlaylistURLs   = 6
	MaxProxyAllowURLs = 128
	// MaxPlaylistStartAt is 2100-01-01T00:00:00Z in Unix seconds.
	MaxPlaylistStartAt = 4102444800
	// A playlist with several pages shows each one for MinPlaylistInterval to
	// MaxPlaylistInterval seconds; a single page never rotates and has no interval.
	MinPlaylistInterval = 10
	MaxPlaylistInterval = 86400
)

// Playlist interval errors are safe to return to API clients.
var (
	ErrSinglePageInterval = errors.New("a single-page playlist has no interval")
	ErrPlaylistInterval   = errors.New("playlists with several pages need an interval of 10-86400 seconds")
)

// ContentMode selects the durable content rendered by the UI.
type ContentMode string

const (
	ContentDefault  ContentMode = "default"
	ContentPlaylist ContentMode = "playlist"
)

// ContentState is the complete controller-owned UI instruction.
type ContentState struct {
	Mode       ContentMode `json:"mode"`
	URLs       []string    `json:"urls,omitempty"`
	ProxyAllow []string    `json:"proxy_allow,omitempty"`
	Interval   int         `json:"interval,omitempty"`
	StartAt    int64       `json:"start_at,omitempty"`
}

// DesiredState is the complete durable content instruction reconciled after a reconnect.
type DesiredState struct {
	Content ContentState `json:"content"`
}

// DefaultState returns the safe state assigned when an agent is provisioned.
// HDMI-CEC is intentionally outside desired state, so this resets only the UI.
func DefaultState() DesiredState {
	return DesiredState{
		Content: ContentState{Mode: ContentDefault},
	}
}

// Validate rejects incomplete or internally inconsistent desired state.
func (state DesiredState) Validate() error {
	return state.Content.Validate()
}

// Valid reports whether operation is a supported HDMI-CEC operation.
func (operation DisplayOperation) Valid() bool {
	switch operation {
	case DisplayOn, DisplayOff, DisplayActive, DisplayMute, DisplayVolumeUp, DisplayVolumeDown:
		return true
	default:
		return false
	}
}

// Validate enforces mode-specific content fields and all playlist bounds.
func (content ContentState) Validate() error {
	switch content.Mode {
	case ContentDefault:
		if len(content.URLs) != 0 || len(content.ProxyAllow) != 0 || content.Interval != 0 || content.StartAt != 0 {
			return errors.New("default content contains playlist fields")
		}
		return nil
	case ContentPlaylist:
		return validatePlaylist(content)
	default:
		return fmt.Errorf("invalid content mode %q", content.Mode)
	}
}

// ProxyTargets returns the sorted canonical playlist and supporting-resource
// destinations authorized by content. An error means no policy may be installed.
func (content ContentState) ProxyTargets() ([]string, error) {
	if err := content.Validate(); err != nil {
		return nil, err
	}
	if content.Mode != ContentPlaylist {
		return []string{}, nil
	}
	unique := make(map[string]struct{}, len(content.URLs)+len(content.ProxyAllow))
	for _, source := range [][]string{content.URLs, content.ProxyAllow} {
		for _, rawURL := range source {
			target, err := destination.FromURL(rawURL)
			if err != nil {
				return nil, err
			}
			unique[target] = struct{}{}
		}
	}
	targets := make([]string, 0, len(unique))
	for target := range unique {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets, nil
}

// validatePlaylist checks playlist sizes, timing values, and every remote URL.
func validatePlaylist(content ContentState) error {
	if len(content.URLs) == 0 || len(content.URLs) > MaxPlaylistURLs {
		return fmt.Errorf("playlist must contain 1-%d URLs", MaxPlaylistURLs)
	}
	if len(content.ProxyAllow) > MaxProxyAllowURLs {
		return fmt.Errorf("proxy allow list exceeds %d URLs", MaxProxyAllowURLs)
	}
	if len(content.URLs) == 1 && content.Interval != 0 {
		return ErrSinglePageInterval
	}
	if len(content.URLs) > 1 && (content.Interval < MinPlaylistInterval || content.Interval > MaxPlaylistInterval) {
		return ErrPlaylistInterval
	}
	if content.StartAt < 0 || content.StartAt > MaxPlaylistStartAt {
		return errors.New("playlist start time is outside supported bounds")
	}
	for _, rawURL := range content.URLs {
		if _, err := destination.ParseURL(rawURL); err != nil {
			return fmt.Errorf("invalid playlist URL: %w", err)
		}
	}
	for _, rawURL := range content.ProxyAllow {
		if _, err := destination.FromURL(rawURL); err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
	}
	return nil
}
