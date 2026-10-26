/*
 * File purpose: Declares the GTK/WebKit renderer, status page, playlist, and
 * proxy controls used by the local IPC service.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#ifndef NEODSE_WEBVIEW_H
#define NEODSE_WEBVIEW_H

#include <gtk/gtk.h>
#include <time.h>
#include <webkit/webkit.h>

#define MAX_VIEWS 6
#define DEFAULT_STATUS_STAGE "waiting_for_playlist"
#define DEFAULT_STATUS_MESSAGE "Waiting for configuration…"

typedef struct
{
    char* urls[MAX_VIEWS];
    int count;
    int interval;
    int active;
    int started;
    time_t start_time;
} Playlist;

/* Initializes the renderer window and its isolated WebKit network session. */
void webview_init(void);
void webview_destroy(void);

/* Records the application loop that must stop when the window closes. */
void webview_set_main_loop(GMainLoop* main_loop);

/* Applies a loopback proxy endpoint on the GTK main thread. */
void webview_set_proxy_config(const char* url);

/* Reports whether both proxy routing and credentials are ready. */
gboolean webview_is_ready_for_remote_content(void);

/* Caches status fields and updates the built-in page on the GTK main thread. */
void webview_set_default_status(const char* agent_name, const char* friendly_name,
    const char* agent_ip, const char* tunnel_ip, const char* stage, const char* severity,
    const char* message);

/* Shows a transient overlay; the caller must run on the GTK main thread. */
void webview_show_banner(const char* message, const char* severity, guint duration_seconds);

/* Restores the built-in page; the caller must run on the GTK main thread. */
void webview_restore_default(void);

/* Replaces proxy credentials on the GTK main thread. */
void webview_set_proxy_auth(const char* agent_id, const char* token);

/* Replaces the active playlist and schedules its clock-based rotation. */
void playlist_apply(char** urls, int count, int interval, time_t start_time);

/* Reloads every playlist document without cached data or replacing its WebKit view. */
void playlist_reload(void);

/* Resynchronizes playlist rotation without reloading its WebKit documents. */
void playlist_sync(int interval, time_t start_time);

#endif
