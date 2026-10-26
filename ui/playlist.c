/*
 * File purpose: Schedules playlist rotation from wall-clock time, reloads and
 * retries playlist views, and restores the local waiting screen.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"

#define PROXY_RETRY_SECONDS 10

static void start_playback_timer(void);
static void update_from_clock(void);

/* stop_playback_timer removes clock reconciliation without cancelling page recovery. */
static void stop_playback_timer(void)
{
    if (renderer_state()->rotation_timer != 0)
    {
        g_source_remove(renderer_state()->rotation_timer);
        renderer_state()->rotation_timer = 0;
    }
}

/* stop_timers removes playback and recovery sources before views are discarded. */
void stop_timers(void)
{
    stop_playback_timer();
    for (int i = 0; i < MAX_VIEWS; i++)
    {
        if (renderer_state()->retry_timers[i] != 0)
        {
            g_source_remove(renderer_state()->retry_timers[i]);
            renderer_state()->retry_timers[i] = 0;
        }
    }
}

/* retry_playlist_view_cb reloads one still-active playlist view. */
static gboolean retry_playlist_view_cb(gpointer user_data)
{
    int index = GPOINTER_TO_INT(user_data);
    if (index < 0 || index >= MAX_VIEWS)
    {
        return G_SOURCE_REMOVE;
    }

    renderer_state()->retry_timers[index] = 0;
    if (renderer_state()->views[index] != NULL && renderer_state()->playlist.active)
    {
        g_print("[UI] Retrying playlist view index=%d\n", index);
        webkit_web_view_reload(renderer_state()->views[index]);
    }
    return G_SOURCE_REMOVE;
}

/* schedule_playlist_retry coalesces retries for one failed playlist view. */
void schedule_playlist_retry(int index)
{
    if (index < 0 || index >= MAX_VIEWS || renderer_state()->retry_timers[index] != 0
        || renderer_state()->views[index] == NULL || !renderer_state()->playlist.active)
    {
        return;
    }
    renderer_state()->retry_timers[index] = g_timeout_add_seconds(
        PROXY_RETRY_SECONDS, retry_playlist_view_cb, GINT_TO_POINTER(index));
}

/* playlist_record_view_failure keeps each active page's recovery independent. */
void playlist_record_view_failure(WebKitWebView* view, int index, gboolean failed)
{
    if (index < 0 || index >= MAX_VIEWS || renderer_state()->views[index] != view || view == NULL)
    {
        return;
    }
    if (failed)
    {
        renderer_state()->proxy_content_failures |= 1U << index;
        schedule_playlist_retry(index);
    }
    else
    {
        renderer_state()->proxy_content_failures &= ~(1U << index);
        if (renderer_state()->retry_timers[index] != 0)
        {
            g_source_remove(renderer_state()->retry_timers[index]);
            renderer_state()->retry_timers[index] = 0;
        }
    }
    update_overlays();
}

/* playlist_reload refreshes every playlist document and resource without cached data. */
void playlist_reload(void)
{
    if (!renderer_state()->playlist.active)
    {
        return;
    }
    for (int i = 0; i < renderer_state()->playlist.count; i++)
    {
        if (renderer_state()->retry_timers[i] != 0)
        {
            g_source_remove(renderer_state()->retry_timers[i]);
            renderer_state()->retry_timers[i] = 0;
        }
        if (renderer_state()->views[i] != NULL)
        {
            webkit_web_view_reload_bypass_cache(renderer_state()->views[i]);
        }
    }
}

/* playlist_sync resets only scheduling and visible position, preserving every loaded view. */
void playlist_sync(int interval, time_t start_time)
{
    if (!renderer_state()->playlist.active)
    {
        return;
    }
    stop_playback_timer();
    renderer_state()->playlist.interval = interval;
    renderer_state()->playlist.start_time = start_time;
    renderer_state()->playlist.started = 0;
    start_playback_timer();
}

/* clear_views stops and removes every remote playlist view from the stack. */
void clear_views(void)
{
    for (int i = 0; i < MAX_VIEWS; i++)
    {
        WebKitWebView* view = renderer_state()->views[i];
        if (view != NULL)
        {
            /* Discarded views must not schedule work during teardown signals. */
            renderer_state()->views[i] = NULL;
            webkit_web_view_stop_loading(view);
            gtk_stack_remove(GTK_STACK(renderer_state()->stack), GTK_WIDGET(view));
        }
    }
    renderer_state()->proxy_content_failures = 0;
}

/* show_index makes one validated playlist position visible. */
static void show_index(int index)
{
    if (index < 0 || index >= renderer_state()->playlist.count || renderer_state()->stack == NULL)
    {
        return;
    }

    GtkWidget* view = GTK_WIDGET(renderer_state()->views[index]);
    gtk_stack_set_visible_child(GTK_STACK(renderer_state()->stack), view);
    gtk_widget_grab_focus(view);
}

/* update_from_clock derives the active playlist position from wall-clock time. */
static void update_from_clock(void)
{
    if (!renderer_state()->playlist.active || renderer_state()->playlist.count <= 0)
    {
        return;
    }

    time_t now = time(NULL);

    if (now < renderer_state()->playlist.start_time)
    {
        renderer_state()->playlist.started = 0;
        show_waiting_screen();
        return;
    }

    /* A single page has no interval and never rotates. */
    int index = 0;
    if (renderer_state()->playlist.count > 1 && renderer_state()->playlist.interval > 0)
    {
        gint64 elapsed = (gint64)now - (gint64)renderer_state()->playlist.start_time;
        index = (int)((elapsed / renderer_state()->playlist.interval)
            % renderer_state()->playlist.count);
    }

    renderer_state()->playlist.started = 1;
    show_index(index);
}

/* rotation_cb refreshes clock-based playlist selection once per timer tick. */
static gboolean rotation_cb(gpointer data)
{
    (void)data;
    update_from_clock();
    return TRUE;
}

/* start_playback_timer reconciles wall-clock changes before and after activation. */
static void start_playback_timer(void)
{
    update_from_clock();
    if (renderer_state()->rotation_timer == 0)
    {
        renderer_state()->rotation_timer = g_timeout_add_seconds(1, rotation_cb, NULL);
    }
}

/* playlist_apply rebuilds remote views and starts or schedules their rotation. */
void playlist_apply(char** urls, int count, int interval, time_t start_time)
{
    stop_timers();
    clear_views();

    if (count > MAX_VIEWS)
    {
        count = MAX_VIEWS;
    }

    if (count <= 0)
    {
        renderer_state()->playlist.count = 0;
        renderer_state()->playlist.interval = interval;
        renderer_state()->playlist.active = 0;
        renderer_state()->playlist.started = 0;
        renderer_state()->playlist.start_time = start_time;

        show_waiting_screen();

        return;
    }

    renderer_state()->playlist.count = count;
    renderer_state()->playlist.interval = interval;
    renderer_state()->playlist.start_time = start_time;
    renderer_state()->playlist.active = 1;
    renderer_state()->playlist.started = 0;

    for (int i = 0; i < count; i++)
    {
        renderer_state()->views[i] = create_web_view();
        g_signal_connect(renderer_state()->views[i], "load-changed",
            G_CALLBACK(playlist_view_load_changed), GINT_TO_POINTER(i));
        g_signal_connect(renderer_state()->views[i], "load-failed",
            G_CALLBACK(playlist_view_load_failed), GINT_TO_POINTER(i));
        g_signal_connect(renderer_state()->views[i], "web-process-terminated",
            G_CALLBACK(playlist_view_process_terminated), GINT_TO_POINTER(i));
        g_signal_connect(renderer_state()->views[i], "decide-policy",
            G_CALLBACK(playlist_view_decide_policy), GINT_TO_POINTER(i));
        webkit_web_view_load_uri(renderer_state()->views[i], urls[i]);

        char* name = g_strdup_printf("view-%d", i);
        gtk_stack_add_named(
            GTK_STACK(renderer_state()->stack), GTK_WIDGET(renderer_state()->views[i]), name);
        g_free(name);
    }

    if (renderer_state()->stack != NULL)
    {
        gtk_widget_set_visible(GTK_WIDGET(renderer_state()->stack), TRUE);
    }

    start_playback_timer();
    if (renderer_state()->playlist.started)
    {
        g_print("[UI] Playlist activated count=%d interval=%d\n", renderer_state()->playlist.count,
            renderer_state()->playlist.interval);
    }
    else
    {
        g_print("[UI] Playlist scheduled count=%d start_at=%" G_GINT64_FORMAT "\n",
            renderer_state()->playlist.count, (gint64)start_time);
    }
}

/* webview_restore_default clears remote content and returns to local status. */
void webview_restore_default(void)
{
    stop_timers();
    clear_views();
    renderer_state()->playlist.count = 0;
    renderer_state()->playlist.interval = 0;
    renderer_state()->playlist.active = 0;
    renderer_state()->playlist.started = 0;
    renderer_state()->playlist.start_time = time(NULL);
    renderer_state()->proxy_relay_failure = FALSE;
    if (renderer_state()->custom_banner_timer != 0)
    {
        g_source_remove(renderer_state()->custom_banner_timer);
        renderer_state()->custom_banner_timer = 0;
    }
    g_clear_pointer(&renderer_state()->custom_banner_message, g_free);
    g_clear_pointer(&renderer_state()->custom_banner_severity, g_free);
    update_overlays();
    show_waiting_screen();
}
