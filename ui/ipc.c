/*
 * File purpose: Implements the authenticated Unix-domain command server that
 * validates agent requests and marshals renderer work onto the GTK main thread.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#define _GNU_SOURCE

#include "ipc.h"
#include "validation.h"
#include "webview.h"

#include <json-glib/json-glib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RELOAD_DEBOUNCE_MS 2000
#define APPLY_TIMEOUT_SECONDS 15
#define STATUS_FIELD_MAX 256
#define STATUS_MESSAGE_MAX 2048
#define BANNER_MESSAGE_MAX_CHARS 256

typedef enum
{
    UPDATE_NONE,
    UPDATE_PROXY_CONFIG,
    UPDATE_PROXY_AUTH,
    UPDATE_STATUS,
    UPDATE_BANNER,
    UPDATE_RELOAD,
    UPDATE_PLAYBACK
} UpdateKind;

typedef struct
{
    char** urls;
    int count;
    int interval;
    time_t start_time;

    gboolean is_default;
    UpdateKind update;
    char* fields[7];
    guint duration_seconds;
    gint references;
    GMutex mutex;
    GCond condition;
    gboolean done;
    gboolean applied;
    gboolean cancelled;
} Message;

static gint shutting_down;
static Message* pending_message = NULL;
static guint pending_apply_timer = 0;

/* ---------- memory ---------- */

/* new_message allocates synchronized playlist work with safe scheduling
 * defaults. */
static Message* new_message(void)
{
    Message* m = calloc(1, sizeof(Message));
    if (m == NULL)
    {
        return NULL;
    }
    m->references = 1;
    m->start_time = time(NULL);
    g_mutex_init(&m->mutex);
    g_cond_init(&m->condition);
    return m;
}

/* message_ref retains work shared between the IPC and GTK threads. */
static void message_ref(Message* m) { g_atomic_int_inc(&m->references); }

/* message_unref releases shared work and its owned URL array at the final
 * reference. */
static void message_unref(Message* m)
{
    if (m == NULL || !g_atomic_int_dec_and_test(&m->references))
    {
        return;
    }

    if (m->urls != NULL)
    {
        for (int i = 0; i < m->count; i++)
        {
            free(m->urls[i]);
        }
        free(m->urls);
    }
    for (guint i = 0; i < G_N_ELEMENTS(m->fields); i++)
    {
        free(m->fields[i]);
    }

    g_cond_clear(&m->condition);
    g_mutex_clear(&m->mutex);
    free(m);
}

/* complete_message records the GTK result and wakes a waiting IPC request. */
static void complete_message(Message* m, gboolean applied)
{
    g_mutex_lock(&m->mutex);
    m->done = TRUE;
    m->applied = applied;
    g_cond_broadcast(&m->condition);
    g_mutex_unlock(&m->mutex);
}

/* message_can_apply rejects work whose IPC waiter already timed out. */
static gboolean message_can_apply(Message* m)
{
    gboolean allowed;
    g_mutex_lock(&m->mutex);
    allowed = !m->cancelled;
    g_mutex_unlock(&m->mutex);
    return allowed;
}

/* wait_for_message blocks for bounded GTK application and cancels on timeout.
 */
static gboolean wait_for_message(Message* m)
{
    gint64 deadline = g_get_monotonic_time() + (APPLY_TIMEOUT_SECONDS * G_TIME_SPAN_SECOND);
    g_mutex_lock(&m->mutex);
    while (!m->done)
    {
        if (g_atomic_int_get(&shutting_down))
        {
            m->cancelled = TRUE;
            g_mutex_unlock(&m->mutex);
            return FALSE;
        }
        if (!g_cond_wait_until(
                &m->condition, &m->mutex, MIN(deadline, g_get_monotonic_time() + 100000))
            && g_get_monotonic_time() >= deadline)
        {
            m->cancelled = TRUE;
            g_mutex_unlock(&m->mutex);
            return FALSE;
        }
    }
    gboolean applied = m->applied;
    g_mutex_unlock(&m->mutex);
    return applied;
}

/* node_is_string strictly identifies JSON string values. */
static gboolean node_is_string(JsonNode* node)
{
    return node != NULL && JSON_NODE_HOLDS_VALUE(node)
        && json_node_get_value_type(node) == G_TYPE_STRING;
}

/* node_is_integer strictly identifies signed 64-bit JSON integer values. */
static gboolean node_is_integer(JsonNode* node)
{
    return node != NULL && JSON_NODE_HOLDS_VALUE(node)
        && json_node_get_value_type(node) == G_TYPE_INT64;
}

/* object_has_only_members rejects unknown fields before command dispatch. */
static gboolean object_has_only_members(
    JsonObject* object, const char* const* allowed, size_t allowed_count)
{
    GList* members = json_object_get_members(object);
    for (GList* item = members; item != NULL; item = item->next)
    {
        const char* name = item->data;
        gboolean found = FALSE;
        for (size_t index = 0; index < allowed_count; index++)
        {
            if (g_strcmp0(name, allowed[index]) == 0)
            {
                found = TRUE;
                break;
            }
        }
        if (!found)
        {
            g_list_free(members);
            return FALSE;
        }
    }
    g_list_free(members);
    return TRUE;
}

/* optional_string_member reads one bounded string or supplies its fallback. */
static gboolean optional_string_member(
    JsonObject* object, const char* name, const char* fallback, size_t maximum, const char** value)
{
    if (!json_object_has_member(object, name))
    {
        *value = fallback;
        return TRUE;
    }
    JsonNode* node = json_object_get_member(object, name);
    if (!node_is_string(node))
    {
        return FALSE;
    }
    const char* candidate = json_node_get_string(node);
    if (candidate == NULL || strlen(candidate) > maximum)
    {
        return FALSE;
    }
    *value = candidate;
    return TRUE;
}

/* string_has_nonspace rejects empty and ASCII-whitespace-only banner text. */
static gboolean string_has_nonspace(const char* value)
{
    for (const unsigned char* p = (const unsigned char*)value; *p != '\0'; p++)
    {
        if (!g_ascii_isspace(*p))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* ---------- actual apply on GTK thread ---------- */

/* apply_message_now commits default or playlist state on the GTK main thread.
 */
static void apply_message_now(Message* m)
{
    if (!message_can_apply(m))
    {
        complete_message(m, FALSE);
        return;
    }
    switch (m->update)
    {
    case UPDATE_PROXY_CONFIG:
        webview_set_proxy_config(m->fields[0]);
        break;
    case UPDATE_PROXY_AUTH:
        webview_set_proxy_auth(m->fields[0], m->fields[1]);
        break;
    case UPDATE_STATUS:
        webview_set_default_status(m->fields[0], m->fields[1], m->fields[2], m->fields[3],
            m->fields[4], m->fields[5], m->fields[6]);
        break;
    case UPDATE_BANNER:
        webview_show_banner(m->fields[0], m->fields[1], m->duration_seconds);
        break;
    case UPDATE_RELOAD:
        playlist_reload();
        break;
    case UPDATE_PLAYBACK:
        playlist_sync(m->interval, m->start_time);
        break;
    case UPDATE_NONE:
        break;
    }
    if (m->update != UPDATE_NONE)
    {
        complete_message(m, TRUE);
        return;
    }
    if (m->is_default)
    {
        webview_restore_default();
        g_print("[IPC] Default display applied\n");
        complete_message(m, TRUE);
        return;
    }

    playlist_apply(m->urls, m->count, m->interval, m->start_time);
    g_print("[IPC] Playlist applied count=%d interval=%d start_at=%" G_GINT64_FORMAT "\n", m->count,
        m->interval, (gint64)m->start_time);
    complete_message(m, TRUE);
}

/* ---------- debounce ---------- */

/* apply_pending_message consumes the debounced message from the GLib source. */
static gboolean apply_pending_message(gpointer data)
{
    (void)data;

    Message* m = pending_message;
    pending_message = NULL;
    pending_apply_timer = 0;

    if (m != NULL)
    {
        apply_message_now(m);
        message_unref(m);
    }

    return G_SOURCE_REMOVE;
}

/* schedule_pending_message starts the debounce timer once remote content is
 * ready. */
static void schedule_pending_message(void)
{
    if (pending_message == NULL || pending_apply_timer != 0
        || !webview_is_ready_for_remote_content())
    {
        return;
    }

    pending_apply_timer = g_timeout_add(RELOAD_DEBOUNCE_MS, apply_pending_message, NULL);
}

/* queue_message supersedes stale work and applies or defers the newest command.
 */
static void queue_message(Message* m)
{
    if (pending_apply_timer != 0)
    {
        g_source_remove(pending_apply_timer);
        pending_apply_timer = 0;
    }

    if (pending_message != NULL)
    {
        complete_message(pending_message, FALSE);
        message_unref(pending_message);
        pending_message = NULL;
    }

    pending_message = m;
    if (m->is_default)
    {
        apply_pending_message(NULL);
        return;
    }
    if (!webview_is_ready_for_remote_content())
    {
        g_print("[IPC] Playlist waiting for proxy configuration and credentials\n");
    }
    schedule_pending_message();
}

/* queue_message_idle transfers one IPC-thread message into GTK-owned state. */
static gboolean queue_message_idle(gpointer data)
{
    Message* m = data;
    if (g_atomic_int_get(&shutting_down))
    {
        complete_message(m, FALSE);
        message_unref(m);
        return G_SOURCE_REMOVE;
    }
    if (m->update != UPDATE_NONE)
    {
        apply_message_now(m);
        message_unref(m);
        return G_SOURCE_REMOVE;
    }
    queue_message(m);
    return G_SOURCE_REMOVE;
}

/* ipc_proxy_state_changed retries queued playlist work after proxy readiness
 * changes. */
void ipc_proxy_state_changed(void) { schedule_pending_message(); }

/* submit_message transfers one owned request to GTK and optionally awaits
 * application. */
static gboolean submit_message(Message* m, gboolean wait_for_application, char** error_message)
{
    if (wait_for_application)
    {
        message_ref(m);
    }
    g_idle_add(queue_message_idle, m);
    if (!wait_for_application)
    {
        return TRUE;
    }
    gboolean applied = wait_for_message(m);
    message_unref(m);
    if (!applied && error_message != NULL)
    {
        *error_message = g_strdup("UI application timed out, was cancelled, or was superseded");
    }
    return applied;
}

/* submit_update copies validated fields before releasing the JSON parser. */
static gboolean submit_update(UpdateKind kind, const char* const* fields, guint count,
    guint duration_seconds, gboolean wait_for_application, char** error_message)
{
    Message* m = new_message();
    if (m == NULL)
    {
        return FALSE;
    }
    m->update = kind;
    m->duration_seconds = duration_seconds;
    g_assert(count <= G_N_ELEMENTS(m->fields));
    for (guint i = 0; i < count; i++)
    {
        m->fields[i] = strdup(fields[i]);
        if (m->fields[i] == NULL)
        {
            message_unref(m);
            return FALSE;
        }
    }
    return submit_message(m, wait_for_application, error_message);
}

/* ---------- JSON parsing ---------- */

/* ipc_process_message validates and dispatches one strict JSON command object.
 */
gboolean ipc_process_message(const char* msg, char** error_message, gboolean wait_for_application)
{
    if (msg == NULL || strnlen(msg, NEODSE_IPC_MAX_BYTES + 1U) > NEODSE_IPC_MAX_BYTES
        || g_atomic_int_get(&shutting_down))
    {
        return FALSE;
    }
    JsonParser* parser = json_parser_new();
    json_parser_set_strict(parser, TRUE);
    GError* error = NULL;

    if (!json_parser_load_from_data(parser, msg, -1, &error))
    {
        /* Parser diagnostics can quote credentials from the rejected payload. */
        g_printerr("[IPC] ! Invalid JSON command\n");
        g_clear_error(&error);
        g_object_unref(parser);
        return FALSE;
    }

    JsonNode* root = json_parser_get_root(parser);
    if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root))
    {
        g_object_unref(parser);
        return FALSE;
    }

    JsonObject* obj = json_node_get_object(root);
    JsonNode* cmd_node = json_object_get_member(obj, "cmd");
    if (!node_is_string(cmd_node))
    {
        g_object_unref(parser);
        return FALSE;
    }

    const char* cmd = json_node_get_string(cmd_node);

    if (g_strcmp0(cmd, "reload") == 0)
    {
        const char* const allowed[] = { "cmd" };
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed)))
        {
            g_object_unref(parser);
            return FALSE;
        }
        gboolean applied
            = submit_update(UPDATE_RELOAD, NULL, 0, 0, wait_for_application, error_message);
        g_object_unref(parser);
        return applied;
    }

    /* Route WebKit through the agent's loopback proxy relay. */
    if (g_strcmp0(cmd, "proxy_config") == 0)
    {
        const char* const allowed[] = { "cmd", "url" };
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed)))
        {
            g_object_unref(parser);
            return FALSE;
        }
        JsonNode* url_node = json_object_get_member(obj, "url");
        if (!node_is_string(url_node))
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* url = json_node_get_string(url_node);
        if (!neodse_valid_proxy_url(url))
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* fields[] = { url };
        gboolean applied = submit_update(UPDATE_PROXY_CONFIG, fields, G_N_ELEMENTS(fields), 0,
            wait_for_application, error_message);
        g_object_unref(parser);
        return applied;
    }

    if (g_strcmp0(cmd, "status") == 0)
    {
        const char* const allowed[] = { "cmd", "agent_name", "friendly_name", "agent_ip",
            "tunnel_ip", "stage", "severity", "message" };
        const char* agent_name;
        const char* friendly_name;
        const char* agent_ip;
        const char* tunnel_ip;
        const char* stage;
        const char* severity;
        const char* message;
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed))
            || !optional_string_member(obj, "agent_name", "", STATUS_FIELD_MAX, &agent_name)
            || !optional_string_member(obj, "friendly_name", "", STATUS_FIELD_MAX, &friendly_name)
            || !optional_string_member(obj, "agent_ip", "", STATUS_FIELD_MAX, &agent_ip)
            || !optional_string_member(obj, "tunnel_ip", "", STATUS_FIELD_MAX, &tunnel_ip)
            || !optional_string_member(obj, "stage", DEFAULT_STATUS_STAGE, STATUS_FIELD_MAX, &stage)
            || !optional_string_member(obj, "severity", "info", STATUS_FIELD_MAX, &severity)
            || !optional_string_member(
                obj, "message", DEFAULT_STATUS_MESSAGE, STATUS_MESSAGE_MAX, &message)
            || (g_strcmp0(severity, "info") != 0 && g_strcmp0(severity, "success") != 0
                && g_strcmp0(severity, "warning") != 0 && g_strcmp0(severity, "critical") != 0))
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* fields[]
            = { agent_name, friendly_name, agent_ip, tunnel_ip, stage, severity, message };
        gboolean applied = submit_update(
            UPDATE_STATUS, fields, G_N_ELEMENTS(fields), 0, wait_for_application, error_message);
        g_object_unref(parser);
        return applied;
    }

    if (g_strcmp0(cmd, "banner") == 0)
    {
        const char* const allowed[] = { "cmd", "message", "severity", "duration_seconds" };
        JsonNode* message_node = json_object_get_member(obj, "message");
        JsonNode* severity_node = json_object_get_member(obj, "severity");
        JsonNode* duration_node = json_object_get_member(obj, "duration_seconds");
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed))
            || !node_is_string(message_node) || !node_is_string(severity_node)
            || !node_is_integer(duration_node))
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* message = json_node_get_string(message_node);
        const char* severity = json_node_get_string(severity_node);
        gint64 duration = json_node_get_int(duration_node);
        if (message == NULL || !g_utf8_validate(message, -1, NULL)
            || g_utf8_strlen(message, -1) > BANNER_MESSAGE_MAX_CHARS
            || !string_has_nonspace(message)
            || (g_strcmp0(severity, "info") != 0 && g_strcmp0(severity, "warning") != 0
                && g_strcmp0(severity, "critical") != 0)
            || duration < 1 || duration > 300)
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* fields[] = { message, severity };
        gboolean applied = submit_update(UPDATE_BANNER, fields, G_N_ELEMENTS(fields),
            (guint)duration, wait_for_application, error_message);
        g_object_unref(parser);
        return applied;
    }

    /* Configure the credentials WebKit presents when the proxy requests authentication. */
    if (g_strcmp0(cmd, "proxy_auth") == 0)
    {
        const char* const allowed[] = { "cmd", "agent_id", "token" };
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed)))
        {
            g_object_unref(parser);
            return FALSE;
        }
        JsonNode* agent_node = json_object_get_member(obj, "agent_id");
        JsonNode* token_node = json_object_get_member(obj, "token");
        if (!node_is_string(agent_node) || !node_is_string(token_node))
        {
            g_object_unref(parser);
            return FALSE;
        }
        const char* agent_id = json_node_get_string(agent_node);
        const char* token = json_node_get_string(token_node);

        if (!neodse_valid_agent_id(agent_id) || !neodse_valid_proxy_token(token))
        {
            g_printerr("[IPC] ! Invalid proxy_auth credentials\n");
            g_object_unref(parser);
            return FALSE;
        }

        const char* fields[] = { agent_id, token };
        gboolean applied = submit_update(UPDATE_PROXY_AUTH, fields, G_N_ELEMENTS(fields), 0,
            wait_for_application, error_message);
        g_object_unref(parser);
        return applied;
    }

    Message* m = new_message();
    if (m == NULL)
    {
        g_printerr("[IPC] ! Allocation failed\n");
        g_object_unref(parser);
        return FALSE;
    }
    if (g_strcmp0(cmd, "playback") == 0)
    {
        const char* const allowed[] = { "cmd", "interval", "start_at" };
        JsonNode* interval_node = json_object_get_member(obj, "interval");
        JsonNode* start_node = json_object_get_member(obj, "start_at");
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed))
            || (interval_node != NULL && !node_is_integer(interval_node))
            || !node_is_integer(start_node))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }
        gint64 interval = interval_node == NULL ? 0 : json_node_get_int(interval_node);
        gint64 start = json_node_get_int(start_node);
        if (!neodse_valid_playlist_timing(interval, start))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }
        m->interval = (int)interval;
        m->start_time = (time_t)start;
        m->update = UPDATE_PLAYBACK;
        g_object_unref(parser);
        return submit_message(m, wait_for_application, error_message);
    }
    if (g_strcmp0(cmd, "default") == 0)
    {
        const char* const allowed[] = { "cmd" };
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed)))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }
        m->is_default = TRUE;
        g_object_unref(parser);
        return submit_message(m, wait_for_application, error_message);
    }

    if (g_strcmp0(cmd, "playlist") == 0)
    {
        const char* const allowed[] = { "cmd", "urls", "interval", "start_at" };
        if (!object_has_only_members(obj, allowed, G_N_ELEMENTS(allowed)))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }
        if (json_object_has_member(obj, "interval"))
        {
            JsonNode* interval_node = json_object_get_member(obj, "interval");
            if (!node_is_integer(interval_node))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
            gint64 interval = json_node_get_int(interval_node);
            if (!neodse_valid_playlist_timing(interval, 0))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
            m->interval = (int)interval;
        }

        if (json_object_has_member(obj, "start_at"))
        {
            JsonNode* start_node = json_object_get_member(obj, "start_at");
            if (!node_is_integer(start_node))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
            gint64 start = json_node_get_int(start_node);
            if (!neodse_valid_playlist_timing(0, start))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
            m->start_time = start == 0 ? time(NULL) : (time_t)start;
        }
        else
        {
            m->start_time = time(NULL);
        }

        JsonNode* urls_node = json_object_get_member(obj, "urls");
        if (urls_node == NULL || !JSON_NODE_HOLDS_ARRAY(urls_node))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }

        JsonArray* arr = json_node_get_array(urls_node);

        guint count = json_array_get_length(arr);
        if (count == 0 || count > MAX_VIEWS || !neodse_valid_playlist_interval(m->interval, count))
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }

        m->count = (int)count;

        m->urls = calloc((size_t)m->count, sizeof(char*));
        if (m->urls == NULL)
        {
            g_object_unref(parser);
            message_unref(m);
            return FALSE;
        }

        for (int i = 0; i < m->count; i++)
        {
            JsonNode* url_node = json_array_get_element(arr, (guint)i);
            if (!node_is_string(url_node))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
            const char* url = json_node_get_string(url_node);
            if (!neodse_valid_remote_url(url))
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }

            m->urls[i] = strdup(url);
            if (m->urls[i] == NULL)
            {
                g_object_unref(parser);
                message_unref(m);
                return FALSE;
            }
        }

        g_print("[IPC] Playlist accepted count=%d interval=%d "
                "start_at=%" G_GINT64_FORMAT "\n",
            m->count, m->interval, (gint64)m->start_time);
        g_object_unref(parser);
        return submit_message(m, wait_for_application, error_message);
    }

    g_object_unref(parser);
    message_unref(m);
    return FALSE;
}

/* ipc_cancel_pending wakes waiters and discards GTK-owned pending work. */
void ipc_cancel_pending(void)
{
    g_atomic_int_set(&shutting_down, TRUE);
    if (pending_apply_timer != 0)
    {
        g_source_remove(pending_apply_timer);
        pending_apply_timer = 0;
    }
    if (pending_message != NULL)
    {
        complete_message(pending_message, FALSE);
        message_unref(pending_message);
        pending_message = NULL;
    }
}
