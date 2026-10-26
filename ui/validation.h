/*
 * File purpose: Declares the trust-boundary validators shared by renderer IPC
 * parsing and socket setup.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#ifndef NEODSE_VALIDATION_H
#define NEODSE_VALIDATION_H

#include <glib.h>
#include <stddef.h>
#include <sys/types.h>

/* Several pages rotate every 10-86400 seconds; a single page has interval 0. */
#define PLAYLIST_INTERVAL_MIN 10
#define PLAYLIST_INTERVAL_MAX 86400
#define PLAYLIST_START_MAX ((gint64)4102444800LL)
#define PLAYLIST_URL_MAX 8192
#define NEODSE_SCALE_MIN 0.5
#define NEODSE_SCALE_MAX 3.0

/* Parses a finite scale within inclusive bounds without changing output on failure. */
gboolean neodse_parse_scale(const char* value, double minimum, double maximum, double* result);

/* Reads a display.env scale, keeping fallback when it is unset or invalid. */
double neodse_env_scale(const char* name, double fallback);

/* Reads a display.env show/hide setting, keeping fallback when it is unset or invalid. */
gboolean neodse_env_visibility(const char* name, gboolean fallback);

/* Accepts bounded HTTP(S) content URLs without embedded credentials. */
gboolean neodse_valid_remote_url(const char* value);

/* Accepts only bounded loopback HTTP proxy endpoints with explicit ports. */
gboolean neodse_valid_proxy_url(const char* value);

/* Accepts a bounded agent identifier from the local control plane. */
gboolean neodse_valid_agent_id(const char* value);

/* Accepts a lowercase hexadecimal proxy token of the required length. */
gboolean neodse_valid_proxy_token(const char* value);

/* Accepts a bounded socket filename directly beneath the NeoDSE runtime directory. */
gboolean neodse_valid_socket_path(const char* value, size_t maximum);

/* Accepts playlist intervals and start times within supported bounds. */
gboolean neodse_valid_playlist_timing(gint64 interval, gint64 start_time);

/* Accepts interval 0 for one page and a rotation interval for several pages. */
gboolean neodse_valid_playlist_interval(gint64 interval, guint count);

/* Accepts a local peer owned by root or by the configured agent account. */
gboolean neodse_valid_peer_uid(uid_t peer_uid, uid_t agent_uid);

/* Identifies HTTP responses that indicate proxy-layer unavailability. */
gboolean neodse_proxy_failure_status(guint status);

/* Identifies the status stage emitted after an established transport fails. */
gboolean neodse_transport_failure_stage(const char* stage);

#endif
