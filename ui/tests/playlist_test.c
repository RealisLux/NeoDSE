/*
 * File purpose: Exercises production playlist scheduling across wall-clock
 * changes with controlled timers and inert GTK/WebKit boundaries.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "../renderer_state.h"
#include "../validation.h"
#include <string.h>

typedef struct
{
    guint id;
    guint interval;
    guint64 due;
    GSourceFunc callback;
    gpointer data;
    gboolean active;
} TestTimer;

typedef struct
{
    char* url;
    int index;
    int reloads;
    int cache_bypassing_reloads;
} TestView;

static RendererState state;
static TestTimer timers[64];
static guint timer_count;
static guint64 elapsed_seconds;
static time_t wall_clock;
static GtkWidget* visible_view;
static int stack_marker;
static int waiting_marker;
static int created_views;
static int removed_views;
static int loaded_views;
static int reloaded_views;

/* renderer_state exposes the same state structure used by the real playlist. */
RendererState* renderer_state(void) { return &state; }

/* __wrap_time permits clock steps without changing the host clock. */
time_t __wrap_time(time_t* result)
{
    if (result != NULL)
    {
        *result = wall_clock;
    }
    return wall_clock;
}

/* __wrap_g_timeout_add_seconds records deadlines on an independent monotonic clock. */
guint __wrap_g_timeout_add_seconds(guint interval, GSourceFunc callback, gpointer data)
{
    g_assert_cmpuint(interval, >, 0);
    g_assert_cmpuint(timer_count, <, G_N_ELEMENTS(timers));
    guint id = ++timer_count;
    timers[id - 1] = (TestTimer) { .id = id,
        .interval = interval,
        .due = elapsed_seconds + interval,
        .callback = callback,
        .data = data,
        .active = TRUE };
    return id;
}

/* __wrap_g_source_remove makes cancellation observable without a GLib event loop. */
gboolean __wrap_g_source_remove(guint id)
{
    g_assert_cmpuint(id, >, 0);
    g_assert_cmpuint(id, <=, timer_count);
    g_assert_true(timers[id - 1].active);
    timers[id - 1].active = FALSE;
    return TRUE;
}

/* advance_timers dispatches due production callbacks without advancing wall-clock time. */
static void advance_timers(guint seconds)
{
    guint64 target = elapsed_seconds + seconds;
    for (;;)
    {
        TestTimer* next = NULL;
        for (guint i = 0; i < timer_count; i++)
        {
            if (timers[i].active && timers[i].due <= target
                && (next == NULL || timers[i].due < next->due))
            {
                next = &timers[i];
            }
        }
        if (next == NULL)
        {
            break;
        }
        elapsed_seconds = next->due;
        gboolean repeat = next->callback(next->data);
        if (next->active)
        {
            next->active = repeat;
            next->due = elapsed_seconds + next->interval;
        }
    }
    elapsed_seconds = target;
}

/* create_web_view supplies an owned stand-in; production code still owns its lifecycle. */
WebKitWebView* create_web_view(void)
{
    created_views++;
    return (WebKitWebView*)g_new0(TestView, 1);
}

/* g_signal_connect_data accepts signal wiring without starting GTK or WebKit. */
gulong g_signal_connect_data(gpointer instance, const gchar* signal, GCallback handler,
    gpointer data, GClosureNotify destroy, GConnectFlags flags)
{
    (void)instance;
    (void)signal;
    (void)handler;
    (void)data;
    (void)destroy;
    (void)flags;
    return 1;
}

/* gtk_stack_add_named leaves the stand-in view owned until gtk_stack_remove. */
GtkStackPage* gtk_stack_add_named(GtkStack* stack, GtkWidget* child, const char* name)
{
    (void)stack;
    ((TestView*)child)->index = (int)g_ascii_strtoll(name + strlen("view-"), NULL, 10);
    return NULL;
}

/* gtk_stack_remove releases the stand-in view when production clears a playlist. */
void gtk_stack_remove(GtkStack* stack, GtkWidget* child)
{
    (void)stack;
    TestView* view = (TestView*)child;
    if (visible_view == child)
    {
        visible_view = NULL;
    }
    g_free(view->url);
    g_free(view);
    removed_views++;
}

/* gtk_stack_set_visible_child records which production-selected screen is visible. */
void gtk_stack_set_visible_child(GtkStack* stack, GtkWidget* child)
{
    (void)stack;
    visible_view = child;
}

/* gtk_widget_grab_focus accepts the selected view without a display server. */
gboolean gtk_widget_grab_focus(GtkWidget* widget)
{
    (void)widget;
    return TRUE;
}

/* gtk_widget_set_visible accepts the playlist stack's visibility change. */
void gtk_widget_set_visible(GtkWidget* widget, gboolean visible)
{
    (void)widget;
    (void)visible;
}

/* webkit_web_view_load_uri records initial loads so synchronization can preserve them. */
void webkit_web_view_load_uri(WebKitWebView* web_view, const gchar* uri)
{
    TestView* view = (TestView*)web_view;
    g_free(view->url);
    view->url = g_strdup(uri);
    loaded_views++;
}

/* webkit_web_view_reload records document recovery without replacing its view. */
void webkit_web_view_reload(WebKitWebView* view)
{
    g_assert_nonnull(view);
    ((TestView*)view)->reloads++;
    reloaded_views++;
}

/* webkit_web_view_reload_bypass_cache records requests for fresh remote content. */
void webkit_web_view_reload_bypass_cache(WebKitWebView* view)
{
    g_assert_nonnull(view);
    ((TestView*)view)->cache_bypassing_reloads++;
    reloaded_views++;
}

/* Teardown may synchronously emit a final failure from the discarded view. */
void webkit_web_view_stop_loading(WebKitWebView* view)
{
    g_assert_nonnull(view);
    playlist_record_view_failure(view, ((TestView*)view)->index, TRUE);
}

/* show_waiting_screen records the native waiting view selected by production. */
void show_waiting_screen(void) { visible_view = state.waiting_view; }

/* update_overlays is outside the scheduling behavior under test. */
void update_overlays(void) { }

/* These callbacks are connected by production but never emitted by the inert views. */
void playlist_view_load_changed(WebKitWebView* view, WebKitLoadEvent event, gpointer data)
{
    (void)view;
    (void)event;
    (void)data;
}

gboolean playlist_view_decide_policy(WebKitWebView* view, WebKitPolicyDecision* decision,
    WebKitPolicyDecisionType type, gpointer data)
{
    (void)view;
    (void)decision;
    (void)type;
    (void)data;
    return FALSE;
}

gboolean playlist_view_load_failed(
    WebKitWebView* view, WebKitLoadEvent event, const gchar* uri, GError* error, gpointer data)
{
    (void)view;
    (void)event;
    (void)uri;
    (void)error;
    (void)data;
    return FALSE;
}

void playlist_view_process_terminated(
    WebKitWebView* view, WebKitWebProcessTerminationReason reason, gpointer data)
{
    (void)view;
    (void)reason;
    (void)data;
}

/* reset_fixture starts each scenario with independent wall and monotonic clocks. */
static void reset_fixture(void)
{
    memset(&state, 0, sizeof(state));
    memset(timers, 0, sizeof(timers));
    timer_count = 0;
    elapsed_seconds = 0;
    wall_clock = 1000;
    visible_view = NULL;
    created_views = removed_views = loaded_views = reloaded_views = 0;
    state.stack = (GtkWidget*)&stack_marker;
    state.waiting_view = (GtkWidget*)&waiting_marker;
}

/* apply_playlist exercises the public production entry point with distinct documents. */
static void apply_playlist(int count, int interval, time_t start)
{
    char* urls[]
        = { "https://example.test/one", "https://example.test/two", "https://example.test/three" };
    playlist_apply(urls, count, interval, start);
}

/* assert_visible checks externally visible content as well as its activation marker. */
static void assert_visible(int index)
{
    g_assert_true(
        visible_view == (index < 0 ? state.waiting_view : GTK_WIDGET(state.views[index])));
    g_assert_cmpint(state.playlist.started, ==, index >= 0);
}

/* finish_fixture checks that returning to default cancels every timer and frees every view. */
static void finish_fixture(void)
{
    webview_restore_default();
    assert_visible(-1);
    for (guint i = 0; i < timer_count; i++)
    {
        g_assert_false(timers[i].active);
    }
    g_assert_cmpint(created_views, ==, removed_views);
}

/* Forward and backward corrections while waiting must be observed on the next tick. */
static void test_waiting_clock_steps(void)
{
    reset_fixture();
    apply_playlist(3, 10, 2000);
    assert_visible(-1);
    wall_clock = 500;
    advance_timers(5);
    assert_visible(-1);
    wall_clock = 2040;
    advance_timers(1);
    assert_visible(1);
    finish_fixture();
}

/* A relative deadline must not start content early after a backward correction. */
static void test_backward_step_past_original_deadline(void)
{
    reset_fixture();
    apply_playlist(2, 10, 1002);
    wall_clock = 500;
    advance_timers(5);
    assert_visible(-1);
    wall_clock = 1002;
    advance_timers(1);
    assert_visible(0);
    finish_fixture();
}

/* A correction before start_at hides active content and permits activation again. */
static void test_active_clock_rollback(void)
{
    reset_fixture();
    apply_playlist(3, 10, 1000);
    assert_visible(0);
    wall_clock = 1040;
    advance_timers(1);
    assert_visible(1);
    wall_clock = 999;
    advance_timers(1);
    assert_visible(-1);
    wall_clock = 1020;
    advance_timers(1);
    assert_visible(2);
    finish_fixture();
}

/* Initial application must immediately select the current position rather than view zero. */
static void test_initial_clock_position(void)
{
    reset_fixture();
    wall_clock = 1055;
    apply_playlist(3, 10, 1000);
    assert_visible(2);
    finish_fixture();
}

/* A single page has no interval: it stays visible and is never divided by zero. */
static void test_single_page_without_interval(void)
{
    reset_fixture();
    apply_playlist(1, 0, 1000);
    assert_visible(0);
    wall_clock = 1000 + PLAYLIST_INTERVAL_MAX;
    advance_timers(1);
    assert_visible(0);
    playlist_sync(0, wall_clock + 100);
    assert_visible(-1);
    wall_clock += 100;
    advance_timers(1);
    assert_visible(0);
    finish_fixture();
}

/* Timing updates preserve loaded documents and pending failed-document recovery. */
static void test_sync_preserves_views_and_retry(void)
{
    reset_fixture();
    apply_playlist(3, 10, 900);
    WebKitWebView* views[MAX_VIEWS];
    memcpy(views, state.views, sizeof(views));
    schedule_playlist_retry(1);
    guint retry = state.retry_timers[1];
    guint previous_rotation = state.rotation_timer;
    wall_clock = 2000;
    playlist_sync(20, 1980);
    assert_visible(1);
    g_assert_false(timers[previous_rotation - 1].active);
    g_assert_cmpuint(state.retry_timers[1], ==, retry);
    g_assert_true(timers[retry - 1].active);
    g_assert_cmpmem(views, sizeof(views), state.views, sizeof(state.views));
    g_assert_cmpint(created_views, ==, 3);
    g_assert_cmpint(loaded_views, ==, 3);
    advance_timers(10);
    g_assert_cmpint(reloaded_views, ==, 1);
    g_assert_cmpuint(state.retry_timers[1], ==, 0);
    playlist_sync(20, 3000);
    assert_visible(-1);
    wall_clock = 3100;
    advance_timers(1);
    assert_visible(2);
    g_assert_cmpmem(views, sizeof(views), state.views, sizeof(state.views));
    g_assert_cmpint(loaded_views, ==, 3);
    finish_fixture();
}

/* Reload refreshes visible and hidden documents without changing playback or views. */
static void test_reload_all_views(void)
{
    for (int scheduled = 0; scheduled <= 1; scheduled++)
    {
        reset_fixture();
        playlist_reload();
        g_assert_cmpint(reloaded_views, ==, 0);
        apply_playlist(3, 10, scheduled ? 2000 : 990);
        assert_visible(scheduled ? -1 : 1);
        Playlist playlist = state.playlist;
        WebKitWebView* views[MAX_VIEWS];
        memcpy(views, state.views, sizeof(views));
        guint rotation = state.rotation_timer;
        schedule_playlist_retry(0);
        schedule_playlist_retry(2);
        guint retry_first = state.retry_timers[0];
        guint retry_last = state.retry_timers[2];

        playlist_reload();

        g_assert_cmpint(reloaded_views, ==, 3);
        for (int i = 0; i < 3; i++)
        {
            TestView* view = (TestView*)state.views[i];
            g_assert_cmpint(view->cache_bypassing_reloads, ==, 1);
            g_assert_cmpint(view->reloads, ==, 0);
            g_assert_cmpuint(state.retry_timers[i], ==, 0);
        }
        g_assert_false(timers[retry_first - 1].active);
        g_assert_false(timers[retry_last - 1].active);
        g_assert_cmpmem(views, sizeof(views), state.views, sizeof(state.views));
        g_assert_cmpmem(&playlist, sizeof(playlist), &state.playlist, sizeof(state.playlist));
        g_assert_cmpuint(state.rotation_timer, ==, rotation);
        g_assert_true(timers[rotation - 1].active);
        assert_visible(scheduled ? -1 : 1);
        g_assert_cmpint(created_views, ==, 3);
        g_assert_cmpint(loaded_views, ==, 3);
        g_assert_cmpint(removed_views, ==, 0);
        finish_fixture();
        playlist_reload();
        g_assert_cmpint(reloaded_views, ==, 3);
    }
}

/* Replacing or clearing a playlist cancels old playback and recovery callbacks. */
static void test_replacement_and_cancellation(void)
{
    reset_fixture();
    apply_playlist(3, 10, 2000);
    schedule_playlist_retry(1);
    guint previous_rotation = state.rotation_timer;
    guint previous_retry = state.retry_timers[1];
    apply_playlist(2, 10, 900);
    g_assert_false(timers[previous_rotation - 1].active);
    g_assert_false(timers[previous_retry - 1].active);
    g_assert_cmpint(removed_views, ==, 3);
    assert_visible(0);
    finish_fixture();
    advance_timers(100);
    assert_visible(-1);
    apply_playlist(3, 10, 2000);
    playlist_apply(NULL, 0, 10, 2000);
    g_assert_cmpuint(state.rotation_timer, ==, 0);
    advance_timers(100);
    assert_visible(-1);
    finish_fixture();
}

/* Healthy background pages cannot hide failures, and recovery owns only its timer. */
static void test_independent_page_recovery(void)
{
    reset_fixture();
    apply_playlist(3, 10, 900);
    playlist_record_view_failure(state.views[0], 0, TRUE);
    playlist_record_view_failure(state.views[1], 1, TRUE);
    guint first_retry = state.retry_timers[0];
    guint second_retry = state.retry_timers[1];
    g_assert_cmpuint(state.proxy_content_failures, ==, 3);
    g_assert_cmpuint(first_retry, !=, 0);
    g_assert_cmpuint(second_retry, !=, 0);

    playlist_record_view_failure(state.views[0], 0, TRUE);
    g_assert_cmpuint(state.retry_timers[0], ==, first_retry);
    playlist_record_view_failure(state.views[2], 2, FALSE);
    g_assert_cmpuint(state.proxy_content_failures, ==, 3);
    playlist_record_view_failure(state.views[0], 0, FALSE);
    g_assert_cmpuint(state.proxy_content_failures, ==, 2);
    g_assert_cmpuint(state.retry_timers[0], ==, 0);
    g_assert_false(timers[first_retry - 1].active);
    g_assert_cmpuint(state.retry_timers[1], ==, second_retry);

    advance_timers(10);
    g_assert_cmpint(reloaded_views, ==, 1);
    g_assert_cmpuint(state.proxy_content_failures, ==, 2);
    playlist_record_view_failure(state.views[1], 1, FALSE);
    g_assert_cmpuint(state.proxy_content_failures, ==, 0);

    playlist_record_view_failure(state.views[1], 1, TRUE);
    second_retry = state.retry_timers[1];
    apply_playlist(2, 10, 900);
    g_assert_false(timers[second_retry - 1].active);
    g_assert_cmpuint(state.proxy_content_failures, ==, 0);
    for (int i = 0; i < MAX_VIEWS; i++)
    {
        g_assert_cmpuint(state.retry_timers[i], ==, 0);
    }

    /* Wrong slots and discarded/null views can neither mark nor clear live pages. */
    TestView discarded = { 0 };
    guint before_invalid = timer_count;
    playlist_record_view_failure(state.views[0], -1, TRUE);
    playlist_record_view_failure(state.views[0], MAX_VIEWS, TRUE);
    playlist_record_view_failure(NULL, 0, TRUE);
    playlist_record_view_failure(state.views[1], 0, TRUE);
    playlist_record_view_failure((WebKitWebView*)&discarded, 0, TRUE);
    g_assert_cmpuint(state.proxy_content_failures, ==, 0);
    g_assert_cmpuint(timer_count, ==, before_invalid);
    playlist_record_view_failure(state.views[0], 0, TRUE);
    playlist_record_view_failure((WebKitWebView*)&discarded, 0, FALSE);
    g_assert_cmpuint(state.proxy_content_failures, ==, 1);
    finish_fixture();
    g_assert_cmpuint(state.proxy_content_failures, ==, 0);
}

/* main runs production scheduling scenarios without a display server or real time changes. */
int main(int argc, char** argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/playlist/waiting-clock-steps", test_waiting_clock_steps);
    g_test_add_func("/playlist/backward-step-deadline", test_backward_step_past_original_deadline);
    g_test_add_func("/playlist/active-clock-rollback", test_active_clock_rollback);
    g_test_add_func("/playlist/initial-clock-position", test_initial_clock_position);
    g_test_add_func("/playlist/single-page-without-interval", test_single_page_without_interval);
    g_test_add_func("/playlist/sync-preserves-views-retry", test_sync_preserves_views_and_retry);
    g_test_add_func("/playlist/reload-all-views", test_reload_all_views);
    g_test_add_func("/playlist/replacement-cancellation", test_replacement_and_cancellation);
    g_test_add_func("/playlist/independent-page-recovery", test_independent_page_recovery);
    return g_test_run();
}
