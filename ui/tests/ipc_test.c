/*
 * File purpose: Exercises strict renderer command parsing, dispatch, bounds,
 * allocation failures, and cross-thread application acknowledgements.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#define _GNU_SOURCE

#include "../ipc.h"
#include "../validation.h"
#include "../webview.h"

#include <errno.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int proxy_config_calls;
static int proxy_auth_calls;
static int status_calls;
static int banner_calls;
static guint banner_duration;
static int default_calls;
static int playlist_calls;
static int playback_calls;
static int reload_calls;
static int expected_playlist_count = 1;
static gboolean remote_content_ready;
static char* last_value;
static char* last_stage;
static char* last_severity;
static char* last_friendly_name;
static int allocation_call;
static int fail_allocation_at = -1;
static gboolean fail_strdup;

/* __real_calloc names the allocator behind the link-time failure wrapper. */
void* __real_calloc(size_t count, size_t size);

/* __real_strdup names the duplicator behind the link-time failure wrapper. */
char* __real_strdup(const char* value);

/* __wrap_calloc injects a failure at a selected allocation call. */
void* __wrap_calloc(size_t count, size_t size)
{
    allocation_call++;
    if (allocation_call == fail_allocation_at)
    {
        return NULL;
    }
    return __real_calloc(count, size);
}

/* __wrap_strdup injects URL-copy failures for parser cleanup coverage. */
char* __wrap_strdup(const char* value)
{
    if (fail_strdup)
    {
        return NULL;
    }
    return __real_strdup(value);
}

/* webview_init is an inert renderer stub required by the IPC test link. */
void webview_init(void) { }

/* webview_set_main_loop accepts the loop without changing test state. */
void webview_set_main_loop(GMainLoop* main_loop) { (void)main_loop; }

/* webview_set_proxy_config records validated proxy dispatches. */
void webview_set_proxy_config(const char* url)
{
    proxy_config_calls++;
    g_free(last_value);
    last_value = g_strdup(url);
}

/* webview_is_ready_for_remote_content exposes controlled readiness to IPC tests. */
gboolean webview_is_ready_for_remote_content(void) { return remote_content_ready; }

/* webview_set_default_status records validated status dispatches. */
void webview_set_default_status(const char* agent_name, const char* friendly_name,
    const char* agent_ip, const char* tunnel_ip, const char* stage, const char* severity,
    const char* message)
{
    (void)agent_name;
    (void)agent_ip;
    (void)tunnel_ip;
    status_calls++;
    g_free(last_value);
    g_free(last_stage);
    g_free(last_severity);
    g_free(last_friendly_name);
    last_value = g_strdup(message);
    last_stage = g_strdup(stage);
    last_severity = g_strdup(severity);
    last_friendly_name = g_strdup(friendly_name);
}

/* webview_show_banner records validated transient overlay dispatches. */
void webview_show_banner(const char* message, const char* severity, guint duration_seconds)
{
    banner_calls++;
    banner_duration = duration_seconds;
    g_free(last_value);
    last_value = g_strdup_printf("%s:%s", severity, message);
}

/* webview_restore_default counts default-page dispatches. */
void webview_restore_default(void) { default_calls++; }

/* webview_set_proxy_auth records validated credential dispatches without the token. */
void webview_set_proxy_auth(const char* agent_id, const char* token)
{
    (void)token;
    proxy_auth_calls++;
    g_free(last_value);
    last_value = g_strdup(agent_id);
}

static int last_playlist_interval;
static int last_sync_interval;

/* playlist_apply records validated playlist dispatches. */
void playlist_apply(char** urls, int count, int interval, time_t start_time)
{
    (void)urls;
    (void)start_time;
    playlist_calls++;
    last_playlist_interval = interval;
    g_assert_cmpint(count, ==, expected_playlist_count);
}

/* playlist_reload records in-place document reload dispatches. */
void playlist_reload(void) { reload_calls++; }
void playlist_sync(int interval, time_t start_time)
{
    g_assert_cmpint(start_time, ==, 100);
    playback_calls++;
    last_sync_interval = interval;
}

typedef struct
{
    gint done;
    gboolean accepted;
    char* error_message;
    const char* message;
} WaitingMessageResult;

/* process_waiting_playlist submits a synchronous command from a worker thread. */
static gpointer process_waiting_playlist(gpointer user_data)
{
    WaitingMessageResult* result = user_data;
    result->accepted = ipc_process_message(result->message != NULL
            ? result->message
            : "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"]}",
        &result->error_message, TRUE);
    g_atomic_int_set(&result->done, TRUE);
    g_main_context_wakeup(g_main_context_default());
    return NULL;
}

/* process submits one command without waiting and releases unused outputs. */
static gboolean process(const char* message)
{
    char* error_message = NULL;
    gboolean accepted = ipc_process_message(message, &error_message, FALSE);
    g_free(error_message);
    return accepted;
}

/* drain_main_context applies all ready callbacks on the default GLib context. */
static void drain_main_context(void)
{
    while (g_main_context_iteration(NULL, FALSE))
    {
    }
}

/* test_malformed_messages rejects invalid shapes, values, and extra policy fields. */
static void test_malformed_messages(void)
{
    const char* messages[] = { "", "{", "[]", "{}", "{\"cmd\":false}", "{\"cmd\":\"unknown\"}",
        "{\"cmd\":\"default\",\"extra\":true}", "{\"cmd\":\"status\",\"message\":42}",
        "{\"cmd\":\"status\",\"severity\":\"error\"}",
        "{\"cmd\":\"banner\",\"message\":\"\",\"severity\":\"info\",\"duration_seconds\":10}",
        "{\"cmd\":\"banner\",\"message\":\"hello\",\"severity\":\"error\",\"duration_seconds\":10}",
        "{\"cmd\":\"banner\",\"message\":\"hello\",\"severity\":\"info\",\"duration_seconds\":301}",
        "{\"cmd\":\"banner\",\"message\":\"hello\",\"severity\":\"info\"}",
        "{\"cmd\":\"reload\",\"extra\":true}",
        "{\"cmd\":\"playback\",\"start_at\":100,\"extra\":true}",
        "{\"cmd\":\"playback\",\"start_at\":4102444801}", "{\"cmd\":\"playback\",\"interval\":30}",
        "{\"cmd\":\"proxy_config\",\"enabled\":true,\"url\":\"http://127.0.0.1:3129\"}",
        "{\"cmd\":\"proxy_auth\",\"agent_id\":\"display-01\",\"token\":\"bad\"}",
        "{\"cmd\":\"playlist\",\"urls\":[]}",
        "{\"cmd\":\"playlist\",\"urls\":[\"file:///etc/passwd\"]}",
        ("{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"],\"proxy_allow\":[\"https://"
         "example.test\"]}"),
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"],\"interval\":30}",
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test/a\",\"https://example.test/b\"]}",
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test/a\",\"https://example.test/b\"],"
        "\"interval\":9}",
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test/a\",\"https://example.test/b\"],"
        "\"interval\":86401}",
        "{\"cmd\":\"playback\",\"interval\":9,\"start_at\":100}",
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"],\"start_at\":4102444801}",
        "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"],\"extra\":true}" };
    for (size_t index = 0; index < G_N_ELEMENTS(messages); index++)
    {
        g_assert_false(process(messages[index]));
    }
}

/* test_valid_messages dispatches each supported command to the expected stub. */
static void test_valid_messages(void)
{
    const char* token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    g_assert_true(process("{\"cmd\":\"proxy_config\",\"url\":\"http://127.0.0.1:3129\"}"));
    drain_main_context();
    g_assert_cmpint(proxy_config_calls, ==, 1);
    g_assert_cmpstr(last_value, ==, "http://127.0.0.1:3129");

    char* auth = g_strdup_printf("{\"cmd\":\"proxy_auth\",\"agent_id\":\"display-01\","
                                 "\"token\":\"%s\"}",
        token);
    g_assert_true(process(auth));
    g_free(auth);
    drain_main_context();
    g_assert_cmpint(proxy_auth_calls, ==, 1);
    g_assert_cmpstr(last_value, ==, "display-01");

    g_assert_true(process("{\"cmd\":\"status\",\"agent_name\":\"Display\","
                          "\"friendly_name\":\"Left lobby\","
                          "\"stage\":\"waiting_for_playlist\",\"severity\":\"success\","
                          "\"message\":\"Waiting\"}"));
    drain_main_context();
    g_assert_cmpint(status_calls, ==, 1);
    g_assert_cmpstr(last_value, ==, "Waiting");
    g_assert_cmpstr(last_stage, ==, "waiting_for_playlist");
    g_assert_cmpstr(last_severity, ==, "success");
    g_assert_cmpstr(last_friendly_name, ==, "Left lobby");

    g_assert_true(process("{\"cmd\":\"banner\",\"message\":\"Maintenance soon\","
                          "\"severity\":\"warning\",\"duration_seconds\":30}"));
    drain_main_context();
    g_assert_cmpint(banner_calls, ==, 1);
    g_assert_cmpuint(banner_duration, ==, 30);
    g_assert_cmpstr(last_value, ==, "warning:Maintenance soon");

    g_assert_true(process("{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"],"
                          "\"start_at\":0}"));
    g_assert_true(process("{\"cmd\":\"reload\"}"));
    drain_main_context();
    g_assert_cmpint(reload_calls, ==, 1);
    g_assert_true(process("{\"cmd\":\"playback\",\"interval\":30,\"start_at\":100}"));
    drain_main_context();
    g_assert_cmpint(playback_calls, ==, 1);
    g_assert_cmpint(last_sync_interval, ==, 30);
    g_assert_true(process("{\"cmd\":\"playback\",\"start_at\":100}"));
    drain_main_context();
    g_assert_cmpint(last_sync_interval, ==, 0);
    remote_content_ready = TRUE;
    int before = playlist_calls;
    g_assert_true(process("{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"]}"));
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (playlist_calls == before && g_get_monotonic_time() < deadline)
    {
        drain_main_context();
        g_usleep(1000);
    }
    g_assert_cmpint(playlist_calls, ==, before + 1);
    g_assert_cmpint(last_playlist_interval, ==, 0);
    remote_content_ready = FALSE;
    g_assert_true(process("{\"cmd\":\"default\"}"));
    drain_main_context();
    g_assert_cmpint(default_calls, ==, 1);
}

/* test_banner_message_length counts Unicode characters at the acceptance boundary. */
static void test_banner_message_length(void)
{
    const char* characters[] = { "a", "é", "界", "😀" };
    for (guint i = 0; i < G_N_ELEMENTS(characters); i++)
    {
        GString* text = g_string_new(NULL);
        for (int length = 1; length <= 257; length++)
        {
            g_string_append(text, characters[i]);
            if (length < 256)
            {
                continue;
            }
            char* message = g_strdup_printf("{\"cmd\":\"banner\",\"message\":\"%s\","
                                            "\"severity\":\"info\",\"duration_seconds\":10}",
                text->str);
            g_assert_cmpint(process(message), ==, length == 256);
            drain_main_context();
            g_free(message);
        }
        g_string_free(text, TRUE);
    }
}

/* test_bounds rejects oversized playlists and status messages. */
static void test_bounds(void)
{
    GString* urls = g_string_new("{\"cmd\":\"playlist\",\"urls\":[");
    for (int index = 0; index < MAX_VIEWS + 1; index++)
    {
        g_string_append_printf(urls, "%s\"https://example.test/%d\"", index == 0 ? "" : ",", index);
    }
    g_string_append(urls, "]}");
    g_assert_false(process(urls->str));
    g_string_free(urls, TRUE);

    char* large = g_strnfill(2049, 'a');
    char* status = g_strdup_printf("{\"cmd\":\"status\",\"message\":\"%s\"}", large);
    g_assert_false(process(status));
    g_free(status);
    g_free(large);

    large = g_strnfill(1025, 'a');
    char* banner = g_strdup_printf("{\"cmd\":\"banner\",\"message\":\"%s\","
                                   "\"severity\":\"info\",\"duration_seconds\":10}",
        large);
    g_assert_false(process(banner));
    g_free(banner);
    g_free(large);
}

/* test_allocation_failures verifies safe rejection at each owned allocation. */
static void test_allocation_failures(void)
{
    const char* playlist = "{\"cmd\":\"playlist\",\"urls\":[\"https://example.test\"]}";
    allocation_call = 0;
    fail_allocation_at = 1;
    g_assert_false(process(playlist));
    allocation_call = 0;
    fail_allocation_at = 2;
    g_assert_false(process(playlist));
    fail_allocation_at = -1;
    fail_strdup = TRUE;
    g_assert_false(process(playlist));
    fail_strdup = FALSE;
}

static const char* update_messages[] = {
    "{\"cmd\":\"proxy_config\",\"url\":\"http://127.0.0.1:3129\"}",
    ("{\"cmd\":\"proxy_auth\",\"agent_id\":\"display-01\",\"token\":"
     "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}"),
    "{\"cmd\":\"status\",\"message\":\"Updated\"}",
    "{\"cmd\":\"banner\",\"message\":\"Updated\",\"severity\":\"info\",\"duration_seconds\":1}"
};

static int update_calls(void)
{
    return proxy_config_calls + proxy_auth_calls + status_calls + banner_calls;
}

/* wait_for_queued_update observes admission without running the GTK callback. */
static void wait_for_queued_update(WaitingMessageResult* result)
{
    gint64 deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    while (!g_main_context_pending(NULL) && !g_atomic_int_get(&result->done)
        && g_get_monotonic_time() < deadline)
    {
        g_usleep(1000);
    }
    g_assert_false(g_atomic_int_get(&result->done));
    g_assert_true(g_main_context_pending(NULL));
}

/* test_updates_wait_for_application rejects acknowledgements before GTK applies each update. */
static void test_updates_wait_for_application(void)
{
    drain_main_context();
    for (guint i = 0; i < G_N_ELEMENTS(update_messages); i++)
    {
        int before = update_calls();
        WaitingMessageResult result = { .message = update_messages[i] };
        GThread* thread = g_thread_new("ipc-update", process_waiting_playlist, &result);
        wait_for_queued_update(&result);
        g_assert_cmpint(update_calls(), ==, before);
        while (!g_atomic_int_get(&result.done))
        {
            g_main_context_iteration(NULL, TRUE);
        }
        g_thread_join(thread);
        g_assert_true(result.accepted);
        g_assert_null(result.error_message);
        g_assert_cmpint(update_calls(), ==, before + 1);
    }
}

/* test_update_timeout prevents a banner from appearing after its caller received failure. */
static void test_update_timeout(void)
{
    drain_main_context();
    int before = update_calls();
    WaitingMessageResult result = { .message = update_messages[3] };
    GThread* thread = g_thread_new("ipc-timeout", process_waiting_playlist, &result);
    wait_for_queued_update(&result);
    gint64 deadline = g_get_monotonic_time() + 17 * G_TIME_SPAN_SECOND;
    while (!g_atomic_int_get(&result.done) && g_get_monotonic_time() < deadline)
    {
        g_usleep(1000);
    }
    g_assert_true(g_atomic_int_get(&result.done));
    g_thread_join(thread);
    g_assert_false(result.accepted);
    g_assert_nonnull(result.error_message);
    g_free(result.error_message);
    drain_main_context();
    g_assert_cmpint(update_calls(), ==, before);
}

/* test_update_shutdown discards all queued updates before renderer teardown. */
static void test_update_shutdown(void)
{
    if (!g_test_subprocess())
    {
        g_test_trap_subprocess(NULL, 3 * G_TIME_SPAN_SECOND, G_TEST_SUBPROCESS_DEFAULT);
        g_test_trap_assert_passed();
        return;
    }
    for (guint i = 0; i < G_N_ELEMENTS(update_messages); i++)
    {
        g_assert_true(process(update_messages[i]));
    }
    ipc_cancel_pending();
    drain_main_context();
    g_assert_cmpint(update_calls(), ==, 0);
}

/* test_update_allocation_failures rejects incomplete copies before queuing work. */
static void test_update_allocation_failures(void)
{
    int before = update_calls();
    for (guint i = 0; i < G_N_ELEMENTS(update_messages); i++)
    {
        allocation_call = 0;
        fail_allocation_at = 1;
        g_assert_false(process(update_messages[i]));
        fail_allocation_at = -1;
        fail_strdup = TRUE;
        g_assert_false(process(update_messages[i]));
        fail_strdup = FALSE;
    }
    drain_main_context();
    g_assert_cmpint(update_calls(), ==, before);
}

/* test_waits_for_main_thread_application verifies synchronous GTK acknowledgement. */
static void test_waits_for_main_thread_application(void)
{
    WaitingMessageResult result = { 0 };
    playlist_calls = 0;
    remote_content_ready = TRUE;

    GThread* thread = g_thread_new("ipc-wait-test", process_waiting_playlist, &result);
    while (!g_atomic_int_get(&result.done))
    {
        g_main_context_iteration(NULL, TRUE);
    }
    g_thread_join(thread);

    g_assert_true(result.accepted);
    g_assert_null(result.error_message);
    g_assert_cmpint(playlist_calls, ==, 1);
    remote_content_ready = FALSE;
}

/* test_maximum_encoded_playlist covers worst-case escaping of every valid URL. */
static void test_maximum_encoded_playlist(void)
{
    GString* message = g_string_new("{\"cmd\":\"playlist\",\"urls\":[");
    const char* prefix = "https://example.test/";
    for (int index = 0; index < MAX_VIEWS; index++)
    {
        g_string_append_printf(message, "%s\"%s", index == 0 ? "" : ",", prefix);
        for (size_t n = strlen(prefix); n < PLAYLIST_URL_MAX; n++)
        {
            g_string_append(message, "\\u0026");
        }
        g_string_append_c(message, '"');
    }
    g_string_append(message, "],\"interval\":86400}");
    g_assert_cmpuint(message->len, >, 65536);
    g_assert_cmpuint(message->len, <, NEODSE_IPC_MAX_BYTES);
    remote_content_ready = TRUE;
    expected_playlist_count = MAX_VIEWS;
    int before = playlist_calls;
    g_assert_true(process(message->str));
    gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
    while (playlist_calls == before && g_get_monotonic_time() < deadline)
    {
        drain_main_context();
        g_usleep(1000);
    }
    g_assert_cmpint(playlist_calls, ==, before + 1);
    expected_playlist_count = 1;
    remote_content_ready = FALSE;
    g_string_free(message, TRUE);
}

/* test_request_framing rejects trailing requests and embedded terminators. */
static void test_request_framing(void)
{
    const char* inputs[] = { "{}\n", "{}", "{}\n{}\n", "{}\nextra", "{}\0\n" };
    const size_t lengths[] = { 3, 2, 6, 8, 4 };
    for (size_t i = 0; i < G_N_ELEMENTS(inputs); i++)
    {
        int sockets[2];
        g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
        g_assert_cmpint(write(sockets[0], inputs[i], lengths[i]), ==, (ssize_t)lengths[i]);
        close(sockets[0]);
        char buffer[32];
        ssize_t received = ipc_receive_message(sockets[1], buffer, sizeof(buffer));
        if (i == 0)
        {
            g_assert_cmpint(received, ==, 3);
        }
        else
        {
            g_assert_cmpint(received, ==, -1);
        }
        close(sockets[1]);
    }
}

/* trickle_request keeps an incomplete request active beyond an idle timeout. */
static gpointer trickle_request(gpointer data)
{
    int peer = GPOINTER_TO_INT(data);
    for (int i = 0; i < 120; i++)
    {
        if (write(peer, " ", 1) != 1)
        {
            break;
        }
        g_usleep(100000);
    }
    return NULL;
}

/* test_request_deadline bounds the whole request, even if bytes keep arriving. */
static void test_request_deadline(void)
{
    int sockets[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
    GThread* writer = g_thread_new("ipc-trickle", trickle_request, GINT_TO_POINTER(sockets[0]));
    char buffer[512];
    gint64 started = g_get_monotonic_time();
    g_assert_cmpint(ipc_receive_message(sockets[1], buffer, sizeof(buffer)), ==, -1);
    g_assert_cmpint(errno, ==, ETIMEDOUT);
    g_assert_cmpint(g_get_monotonic_time() - started, <, 11 * G_TIME_SPAN_SECOND);
    g_thread_join(writer);
    close(sockets[1]);
    close(sockets[0]);
}

/* test_json_errors_do_not_echo_input keeps parser diagnostics out of journals. */
static void test_json_errors_do_not_echo_input(void)
{
    if (g_test_subprocess())
    {
        g_assert_false(process("{\"cmd\":sensitive_fixture_value}"));
        return;
    }
    g_test_trap_subprocess(NULL, 5 * G_TIME_SPAN_SECOND, G_TEST_SUBPROCESS_DEFAULT);
    g_test_trap_assert_passed();
    g_test_trap_assert_stderr("[IPC] ! Invalid JSON command\n");
    g_test_trap_assert_stderr_unmatched("*sensitive_fixture_value*");
}

/* main registers the IPC parser suite and releases shared test state. */
int main(int argc, char** argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ipc/malformed", test_malformed_messages);
    g_test_add_func("/ipc/json-error-privacy", test_json_errors_do_not_echo_input);
    g_test_add_func("/ipc/valid", test_valid_messages);
    g_test_add_func("/ipc/bounds", test_bounds);
    g_test_add_func("/ipc/banner-message-length", test_banner_message_length);
    g_test_add_func("/ipc/request-framing", test_request_framing);
    g_test_add_func("/ipc/request-deadline", test_request_deadline);
    g_test_add_func("/ipc/allocation-failures", test_allocation_failures);
    g_test_add_func("/ipc/maximum-encoded-playlist", test_maximum_encoded_playlist);
    g_test_add_func(
        "/ipc/waits-for-main-thread-application", test_waits_for_main_thread_application);
    g_test_add_func("/ipc/updates-wait-for-application", test_updates_wait_for_application);
    g_test_add_func("/ipc/update-timeout", test_update_timeout);
    g_test_add_func("/ipc/update-shutdown", test_update_shutdown);
    g_test_add_func("/ipc/update-allocation-failures", test_update_allocation_failures);
    int result = g_test_run();
    drain_main_context();
    g_free(last_value);
    g_free(last_stage);
    g_free(last_severity);
    g_free(last_friendly_name);
    return result;
}
