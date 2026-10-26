/*
 * File purpose: Implements strict validation for every value crossing from the
 * agent into renderer networking, authentication, and playlist state.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "validation.h"
#include <math.h>
#include <string.h>

#define RUNTIME_SOCKET_PREFIX "/run/neodse/"

/* neodse_parse_scale rejects non-finite values before GTK sizing or integer conversion. */
gboolean neodse_parse_scale(const char* value, double minimum, double maximum, double* result)
{
    if (value == NULL || *value == '\0' || result == NULL)
    {
        return FALSE;
    }
    char* end = NULL;
    double parsed = g_ascii_strtod(value, &end);
    if (end == value || *end != '\0' || !isfinite(parsed) || parsed < minimum || parsed > maximum)
    {
        return FALSE;
    }
    *result = parsed;
    return TRUE;
}

/* neodse_env_scale logs each configured scale and every rejected value. */
double neodse_env_scale(const char* name, double fallback)
{
    const char* value = g_getenv(name);
    double scale;

    if (value == NULL || value[0] == '\0')
    {
        return fallback;
    }
    if (!neodse_parse_scale(value, NEODSE_SCALE_MIN, NEODSE_SCALE_MAX, &scale))
    {
        g_printerr("[UI] ! Invalid %s; using %.1f\n", name, fallback);
        return fallback;
    }
    g_print("[UI] %s=%.2f\n", name, scale);
    return scale;
}

/* neodse_env_visibility accepts exactly show or hide. */
gboolean neodse_env_visibility(const char* name, gboolean fallback)
{
    const char* value = g_getenv(name);

    if (g_strcmp0(value, "show") == 0)
    {
        return TRUE;
    }
    if (g_strcmp0(value, "hide") == 0)
    {
        return FALSE;
    }
    if (value != NULL && value[0] != '\0')
    {
        g_printerr("[UI] ! Invalid %s; using %s\n", name, fallback ? "show" : "hide");
    }
    return fallback;
}

/* neodse_valid_remote_url accepts bounded HTTP(S) URLs without user information. */
gboolean neodse_valid_remote_url(const char* value)
{
    if (value == NULL || value[0] == '\0' || strlen(value) > PLAYLIST_URL_MAX)
    {
        return FALSE;
    }

    GError* error = NULL;
    GUri* uri = g_uri_parse(value, G_URI_FLAGS_NONE, &error);
    if (uri == NULL)
    {
        g_clear_error(&error);
        return FALSE;
    }

    const char* scheme = g_uri_get_scheme(uri);
    const char* host = g_uri_get_host(uri);
    gboolean valid = (g_strcmp0(scheme, "http") == 0 || g_strcmp0(scheme, "https") == 0)
        && host != NULL && host[0] != '\0' && strchr(host, ':') == NULL
        && g_uri_get_userinfo(uri) == NULL;
    g_uri_unref(uri);
    return valid;
}

/* neodse_valid_proxy_url confines WebKit proxying to explicit loopback endpoints. */
gboolean neodse_valid_proxy_url(const char* value)
{
    if (value == NULL || value[0] == '\0' || strlen(value) > 256)
    {
        return FALSE;
    }

    GError* error = NULL;
    GUri* uri = g_uri_parse(value, G_URI_FLAGS_NONE, &error);
    if (uri == NULL)
    {
        g_clear_error(&error);
        return FALSE;
    }

    const char* path = g_uri_get_path(uri);
    gint port = g_uri_get_port(uri);
    gboolean valid = g_strcmp0(g_uri_get_scheme(uri), "http") == 0
        && g_strcmp0(g_uri_get_host(uri), "127.0.0.1") == 0 && port > 0 && port <= 65535
        && g_uri_get_userinfo(uri) == NULL
        && (path == NULL || path[0] == '\0' || g_strcmp0(path, "/") == 0)
        && g_uri_get_query(uri) == NULL && g_uri_get_fragment(uri) == NULL;
    g_uri_unref(uri);
    return valid;
}

/* neodse_valid_agent_id accepts the identifier alphabet used in proxy credentials. */
gboolean neodse_valid_agent_id(const char* value)
{
    if (value == NULL)
    {
        return FALSE;
    }
    size_t length = strlen(value);
    if (length == 0 || length > 32 || !g_ascii_isalnum(value[0]))
    {
        return FALSE;
    }
    for (size_t i = 1; i < length; i++)
    {
        if (!g_ascii_isalnum(value[i]) && value[i] != '_' && value[i] != '-')
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* neodse_valid_proxy_token accepts exactly one lowercase SHA-256-style token. */
gboolean neodse_valid_proxy_token(const char* value)
{
    if (value == NULL || strlen(value) != 64)
    {
        return FALSE;
    }
    for (size_t i = 0; i < 64; i++)
    {
        if (!g_ascii_isdigit(value[i]) && (value[i] < 'a' || value[i] > 'f'))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* neodse_valid_socket_path accepts one bounded socket filename under /run/neodse. */
gboolean neodse_valid_socket_path(const char* value, size_t maximum)
{
    const size_t prefix_length = sizeof(RUNTIME_SOCKET_PREFIX) - 1;
    const char* name;

    if (value == NULL || maximum <= prefix_length
        || strncmp(value, RUNTIME_SOCKET_PREFIX, prefix_length) != 0 || strlen(value) >= maximum)
    {
        return FALSE;
    }

    name = value + prefix_length;
    return name[0] != '\0' && strcmp(name, ".") != 0 && strcmp(name, "..") != 0
        && strchr(name, '/') == NULL;
}

/* neodse_valid_playlist_timing enforces the renderer's scheduling limits. */
gboolean neodse_valid_playlist_timing(gint64 interval, gint64 start_time)
{
    return (interval == 0
               || (interval >= PLAYLIST_INTERVAL_MIN && interval <= PLAYLIST_INTERVAL_MAX))
        && start_time >= 0 && start_time <= PLAYLIST_START_MAX;
}

/* neodse_valid_playlist_interval matches the controller's interval rule. */
gboolean neodse_valid_playlist_interval(gint64 interval, guint count)
{
    return count == 1 ? interval == 0 : neodse_valid_playlist_timing(interval, 0) && interval != 0;
}

/* neodse_valid_peer_uid authorizes only root or the configured agent account. */
gboolean neodse_valid_peer_uid(uid_t peer_uid, uid_t agent_uid)
{
    return peer_uid == 0 || peer_uid == agent_uid;
}

/* neodse_proxy_failure_status limits warnings to proxy-specific responses. */
gboolean neodse_proxy_failure_status(guint status)
{
    return status == 407 || (status >= 502 && status <= 504);
}

/* neodse_transport_failure_stage recognizes only the explicit lost stage. */
gboolean neodse_transport_failure_stage(const char* stage)
{
    return g_strcmp0(stage, "connection_lost") == 0;
}
