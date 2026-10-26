/*
 * File purpose: Coordinates the GTK/WebKit renderer lifecycle and proxy networking.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "ipc.h"
#include "renderer_state.h"
#include "validation.h"

#define BLOCKED_PROXY_URL "http://127.0.0.1:1"

static RendererState* current_renderer;

/* disable_gtk_cursor prevents the server-side kiosk cursor from duplicating
 * the client-side pointer drawn by VNC viewers. */
static void disable_gtk_cursor(void)
{
    RendererState* state = renderer_state();
    GtkWidget* widgets[] = { state->window, state->stack, state->waiting_view };

    for (guint i = 0; i < G_N_ELEMENTS(widgets); i++)
    {
        if (widgets[i] != NULL)
        {
            gtk_widget_set_cursor_from_name(widgets[i], "none");
        }
    }
    for (int i = 0; i < MAX_VIEWS; i++)
    {
        if (state->views[i] != NULL)
        {
            gtk_widget_set_cursor_from_name(GTK_WIDGET(state->views[i]), "none");
        }
    }
}

/* enforce_webview_cursor_disabled rejects cursor changes requested by page
 * content after WebKit has processed pointer movement. */
static void enforce_webview_cursor_disabled(
    GObject* object, GParamSpec* property, gpointer user_data)
{
    (void)property;
    (void)user_data;

    GtkWidget* widget = GTK_WIDGET(object);
    GdkCursor* cursor = gtk_widget_get_cursor(widget);
    if (cursor != NULL && g_strcmp0(gdk_cursor_get_name(cursor), "none") == 0)
    {
        return;
    }

    gtk_widget_set_cursor_from_name(widget, "none");
}

/* renderer_state permits state access only from its owning GTK thread. */
RendererState* renderer_state(void)
{
    if (current_renderer == NULL || current_renderer->owner != g_thread_self())
    {
        g_error("Renderer state accessed outside its GTK owner lifetime");
    }
    return current_renderer;
}

/* proxy_authenticate_cb answers WebKit proxy challenges from in-memory
 * credentials. */
static gboolean proxy_authenticate_cb(
    WebKitWebView* view, WebKitAuthenticationRequest* request, gpointer user_data);

/* playlist_view_load_changed records successful completion of a playlist load.
 */
void playlist_view_load_changed(WebKitWebView* view, WebKitLoadEvent load_event, gpointer user_data)
{
    (void)view;

    if (load_event == WEBKIT_LOAD_FINISHED)
    {
        g_print("[UI] Playlist view loaded index=%d\n", GPOINTER_TO_INT(user_data));
    }
}

/* playlist_view_decide_policy observes main-document proxy response failures.
 */
gboolean playlist_view_decide_policy(WebKitWebView* view, WebKitPolicyDecision* decision,
    WebKitPolicyDecisionType decision_type, gpointer user_data)
{
    if (decision_type != WEBKIT_POLICY_DECISION_TYPE_RESPONSE
        || !WEBKIT_IS_RESPONSE_POLICY_DECISION(decision))
    {
        return FALSE;
    }

    WebKitResponsePolicyDecision* response_decision = WEBKIT_RESPONSE_POLICY_DECISION(decision);
    if (!webkit_response_policy_decision_is_main_frame_main_resource(response_decision))
    {
        return FALSE;
    }

    WebKitURIResponse* response = webkit_response_policy_decision_get_response(response_decision);
    guint status = webkit_uri_response_get_status_code(response);
    int index = GPOINTER_TO_INT(user_data);

    playlist_record_view_failure(view, index, neodse_proxy_failure_status(status));

    return FALSE;
}

/* playlist_view_load_failed records failures while allowing policy redirects to
 * continue. */
gboolean playlist_view_load_failed(WebKitWebView* view, WebKitLoadEvent load_event,
    const gchar* failing_uri, GError* error, gpointer user_data)
{
    (void)load_event;
    (void)failing_uri;

    if (error != NULL
        && g_error_matches(error, WEBKIT_POLICY_ERROR,
            WEBKIT_POLICY_ERROR_FRAME_LOAD_INTERRUPTED_BY_POLICY_CHANGE))
    {
        g_print("[UI] Playlist view navigation continued index=%d\n", GPOINTER_TO_INT(user_data));
        return FALSE;
    }
    if (error != NULL
        && g_error_matches(error, WEBKIT_NETWORK_ERROR, WEBKIT_NETWORK_ERROR_CANCELLED))
    {
        return FALSE;
    }

    g_printerr("[UI] ! Playlist view load failed index=%d domain=%u code=%d\n",
        GPOINTER_TO_INT(user_data), error != NULL ? error->domain : 0,
        error != NULL ? error->code : 0);
    playlist_record_view_failure(view, GPOINTER_TO_INT(user_data), TRUE);
    return FALSE;
}

/* playlist_view_process_terminated restores loaded content after a WebKit child
 * crashes while the GTK renderer remains alive. */
void playlist_view_process_terminated(
    WebKitWebView* view, WebKitWebProcessTerminationReason reason, gpointer user_data)
{
    if (reason == WEBKIT_WEB_PROCESS_TERMINATED_BY_API)
    {
        return;
    }

    int index = GPOINTER_TO_INT(user_data);
    g_printerr("[UI] ! Playlist web process terminated index=%d reason=%d\n", index, (int)reason);
    playlist_record_view_failure(view, index, TRUE);
}

/* configure_renderer_settings reads WebKit zoom and status-logo settings. */
static void configure_renderer_settings(void)
{
    RendererState* state = renderer_state();
    state->webview_zoom_level = neodse_env_scale("NEODSE_UI_ZOOM", state->webview_zoom_level);
    state->show_status_logo = neodse_env_visibility("NEODSE_UI_STATUS_LOGO", TRUE);
    state->status_logo_scale
        = neodse_env_scale("NEODSE_STATUS_LOGO_SCALE", state->status_logo_scale);
}

/* create_web_view constructs one locked-down view in the isolated network
 * session. */
WebKitWebView* create_web_view(void)
{
    WebKitWebView* view = WEBKIT_WEB_VIEW(g_object_new(
        WEBKIT_TYPE_WEB_VIEW, "network-session", renderer_state()->network_session, NULL));
    WebKitSettings* settings = webkit_web_view_get_settings(view);

    /* Kiosk shells and remote seats do not necessarily assign initial keyboard
     * focus. Keep playlist views explicitly focusable; show_index() focuses the
     * active one after every playlist transition. */
    gtk_widget_set_focusable(GTK_WIDGET(view), TRUE);

    webkit_settings_set_enable_developer_extras(settings, FALSE);
    webkit_settings_set_enable_write_console_messages_to_stdout(settings, FALSE);
    webkit_settings_set_allow_file_access_from_file_urls(settings, FALSE);
    webkit_settings_set_allow_universal_access_from_file_urls(settings, FALSE);

    webkit_web_view_set_zoom_level(view, renderer_state()->webview_zoom_level);
    g_signal_connect(view, "authenticate", G_CALLBACK(proxy_authenticate_cb), NULL);

    browser_configure_view(view);
    g_signal_connect(view, "notify::cursor", G_CALLBACK(enforce_webview_cursor_disabled), NULL);
    gtk_widget_set_cursor_from_name(GTK_WIDGET(view), "none");
    return view;
}

/* configure_network_proxy routes through the approved proxy or a closed
 * endpoint. */
static void configure_network_proxy(void)
{
    if (renderer_state()->network_session == NULL)
    {
        return;
    }

    if (renderer_state()->proxy_url != NULL)
    {
        WebKitNetworkProxySettings* settings
            = webkit_network_proxy_settings_new(renderer_state()->proxy_url, NULL);

        webkit_network_session_set_proxy_settings(
            renderer_state()->network_session, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, settings);
        webkit_network_proxy_settings_free(settings);
        g_print("[UI] WebKit proxy set to: %s\n", renderer_state()->proxy_url);
        return;
    }

    WebKitNetworkProxySettings* settings
        = webkit_network_proxy_settings_new(BLOCKED_PROXY_URL, NULL);
    webkit_network_session_set_proxy_settings(
        renderer_state()->network_session, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, settings);
    webkit_network_proxy_settings_free(settings);
    g_print("[UI] Remote networking blocked until proxy configuration arrives\n");
}

/* window_close_request_cb stops the renderer loop when its window is closed. */
static gboolean window_close_request_cb(GtkWindow* closing_window, gpointer user_data)
{
    (void)closing_window;
    (void)user_data;

    if (renderer_state()->ui_main_loop != NULL)
    {
        g_main_loop_quit(renderer_state()->ui_main_loop);
    }

    return TRUE;
}

/* ---------- helpers ---------- */

/* proxy_authenticate_cb supplies ephemeral credentials only for proxy
 * challenges. */
static gboolean proxy_authenticate_cb(
    WebKitWebView* view, WebKitAuthenticationRequest* request, gpointer user_data)
{
    (void)view;
    (void)user_data;

    if (!webkit_authentication_request_is_for_proxy(request)
        || renderer_state()->proxy_agent_id == NULL || renderer_state()->proxy_auth_token == NULL)
    {
        /* Website logins and missing proxy credentials must not open GTK's
         * interactive authentication dialog on an unattended display. */
        webkit_authentication_request_cancel(request);
        return TRUE;
    }

    /*
     * NeoDSE owns the session-bound proxy credential lifecycle. Do not allow a
     * credential proposed by WebKit's session cache to override the token most
     * recently delivered by the agent after a 407 challenge.
     */
    webkit_authentication_request_set_can_save_credentials(request, FALSE);
    webkit_authentication_request_set_proposed_credential(request, NULL);

    WebKitCredential* credential;

    credential = webkit_credential_new(renderer_state()->proxy_agent_id,
        renderer_state()->proxy_auth_token, WEBKIT_CREDENTIAL_PERSISTENCE_NONE);

    webkit_authentication_request_authenticate(request, credential);

    webkit_credential_free(credential);

    return TRUE;
}

/* webview_create initializes the single renderer window and network session. */
static void webview_create(void)
{
    renderer_state()->network_session = webkit_network_session_new_ephemeral();
    browser_configure_session(renderer_state()->network_session);
    configure_network_proxy();
    configure_renderer_settings();

    renderer_state()->window = gtk_window_new();
    gtk_window_fullscreen(GTK_WINDOW(renderer_state()->window));

    GtkWidget* overlay = gtk_overlay_new();
    renderer_state()->stack = gtk_stack_new();
    gtk_overlay_set_child(GTK_OVERLAY(overlay), renderer_state()->stack);
    create_overlays(GTK_OVERLAY(overlay));
    renderer_state()->status_logo = create_status_logo();
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), renderer_state()->status_logo);
    create_waiting_screen();
    gtk_stack_add_named(
        GTK_STACK(renderer_state()->stack), renderer_state()->waiting_view, "default");
    gtk_window_set_child(GTK_WINDOW(renderer_state()->window), overlay);

    update_overlays();
    gtk_window_present(GTK_WINDOW(renderer_state()->window));
    disable_gtk_cursor();

    g_signal_connect(
        renderer_state()->window, "close-request", G_CALLBACK(window_close_request_cb), NULL);

    /* Apply any status received before window creation. */
    update_waiting_screen();
}

/* webview_set_proxy_config applies a validated proxy endpoint on the GTK thread. */
void webview_set_proxy_config(const char* url)
{
    g_free(renderer_state()->proxy_url);
    renderer_state()->proxy_url = g_strdup(url);
    configure_network_proxy();

    ipc_proxy_state_changed();
    update_overlays();
}

/* webview_set_default_status refreshes cached status on the GTK thread. */
void webview_set_default_status(const char* agent_name, const char* friendly_name,
    const char* agent_ip, const char* tunnel_ip, const char* stage, const char* severity,
    const char* message)
{
    g_free(renderer_state()->default_agent_name);
    g_free(renderer_state()->default_agent_ip);
    g_free(renderer_state()->default_tunnel_ip);
    g_free(renderer_state()->default_status_stage);
    g_free(renderer_state()->default_status_severity);
    g_free(renderer_state()->default_status_message);

    renderer_state()->default_agent_name
        = g_strdup((agent_name != NULL && agent_name[0] != '\0') ? agent_name : "Unknown agent");

    if (renderer_state()->friendly_name != NULL)
    {
        gboolean has_friendly_name = friendly_name != NULL && friendly_name[0] != '\0';
        gtk_label_set_text(
            GTK_LABEL(renderer_state()->friendly_name), has_friendly_name ? friendly_name : "");
    }

    renderer_state()->default_agent_ip
        = g_strdup((agent_ip != NULL && agent_ip[0] != '\0') ? agent_ip : "IP unavailable");

    renderer_state()->default_tunnel_ip
        = g_strdup((tunnel_ip != NULL && tunnel_ip[0] != '\0') ? tunnel_ip : "unavailable");

    renderer_state()->default_status_stage
        = g_strdup((stage != NULL && stage[0] != '\0') ? stage : DEFAULT_STATUS_STAGE);

    renderer_state()->default_status_severity
        = g_strdup((severity != NULL && severity[0] != '\0') ? severity : "info");

    renderer_state()->default_status_message
        = g_strdup((message != NULL && message[0] != '\0') ? message : DEFAULT_STATUS_MESSAGE);

    g_print("[UI] Waiting status stage=%s severity=%s\n", renderer_state()->default_status_stage,
        renderer_state()->default_status_severity);

    if (neodse_transport_failure_stage(renderer_state()->default_status_stage))
    {
        renderer_state()->transport_failure = TRUE;
    }
    else if (g_strcmp0(renderer_state()->default_status_stage, "proxy_connection_lost") == 0)
    {
        renderer_state()->proxy_relay_failure = TRUE;
    }
    else if (g_strcmp0(renderer_state()->default_status_stage, "proxy_connection_restored") == 0)
    {
        renderer_state()->proxy_relay_failure = FALSE;
    }
    else
    {
        renderer_state()->transport_failure = FALSE;
    }
    update_overlays();
    update_waiting_screen();
}

/* webview_set_proxy_auth replaces ephemeral credentials on the GTK thread. */
void webview_set_proxy_auth(const char* agent_id, const char* token)
{
    g_free(renderer_state()->proxy_agent_id);
    g_free(renderer_state()->proxy_auth_token);
    renderer_state()->proxy_agent_id = g_strdup(agent_id);
    renderer_state()->proxy_auth_token = g_strdup(token);
    renderer_state()->proxy_auth_received = TRUE;
    ipc_proxy_state_changed();
    update_overlays();
}

/* ---------- public API ---------- */

/* webview_init creates the renderer exactly once. */
void webview_init(void)
{
    g_assert(current_renderer == NULL);
    current_renderer = g_new0(RendererState, 1);
    current_renderer->owner = g_thread_self();
    current_renderer->webview_zoom_level = 1.0;
    current_renderer->banner_scale = 1.0;
    current_renderer->friendly_name_scale = 1.0;
    current_renderer->clock_scale = 1.0;
    current_renderer->status_logo_scale = 1.0;
    current_renderer->waiting_logo_scale = 1.0;
    current_renderer->waiting_logo_enabled = TRUE;
    webview_create();
}

/* webview_is_ready_for_remote_content requires both routing and authentication.
 */
gboolean webview_is_ready_for_remote_content(void)
{
    return renderer_state()->proxy_url != NULL && renderer_state()->proxy_auth_received;
}

/* webview_set_main_loop records the loop controlled by the renderer window. */
void webview_set_main_loop(GMainLoop* main_loop) { renderer_state()->ui_main_loop = main_loop; }

/* webview_destroy frees renderer-owned timers, views, strings, and session. */
void webview_destroy(void)
{
    stop_timers();
    destroy_overlays();
    clear_views();
    destroy_waiting_screen();
    g_clear_pointer(&renderer_state()->status_logo_mask, cairo_surface_destroy);
    if (renderer_state()->window != NULL)
    {
        gtk_window_destroy(GTK_WINDOW(renderer_state()->window));
    }
    g_free(renderer_state()->proxy_url);
    g_free(renderer_state()->proxy_agent_id);
    g_free(renderer_state()->proxy_auth_token);
    g_free(renderer_state()->default_agent_name);
    g_free(renderer_state()->default_agent_ip);
    g_free(renderer_state()->default_tunnel_ip);
    g_free(renderer_state()->default_status_stage);
    g_free(renderer_state()->default_status_severity);
    g_free(renderer_state()->default_status_message);
    g_clear_object(&current_renderer->network_session);
    g_free(current_renderer);
    current_renderer = NULL;
}
