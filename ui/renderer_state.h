/*
 * File purpose: Declares the renderer-wide GTK/WebKit state and the internal
 * functions shared by the window, playlist, overlay and browser modules.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#ifndef NEODSE_RENDERER_STATE_H
#define NEODSE_RENDERER_STATE_H
#include "webview.h"

#ifndef NEODSE_ASSET_DIR
#define NEODSE_ASSET_DIR "/usr/share/neodse"
#endif
#define LOGO_ATLAS_PATH NEODSE_ASSET_DIR "/logo-animation-atlas.png"

/* Cells in logo-animation-atlas.png: drawing, completed N, dissolve, blank. */
#define LOGO_FRAME_COUNT 76
#define LOGO_COMPLETED_FRAME 59
#define LOGO_ATLAS_COLUMNS 9
#define LOGO_ATLAS_CELL_WIDTH 650
#define LOGO_ATLAS_CELL_HEIGHT 430

typedef struct
{
    GThread* owner;
    GtkWidget* window;
    GtkWidget* stack;
    WebKitWebView* views[MAX_VIEWS];
    Playlist playlist;
    GtkWidget* waiting_view;
    WebKitNetworkSession* network_session;
    GtkWidget* notification_banner;
    GtkWidget* waiting_logo;
    GtkWidget* waiting_logo_wordmark_area;
    GtkWidget* waiting_logo_animation;
    GtkWidget* waiting_status;
    GtkWidget* waiting_info;
    GtkWidget* friendly_name;
    GtkWidget* clock;
    GtkWidget* status_logo;
    GtkWidget* banner_label;
    GtkWidget* banner_icon;
    guint rotation_timer;
    guint retry_timers[MAX_VIEWS];
    guint custom_banner_timer;
    guint clock_timer;
    guint waiting_logo_timer;
    int waiting_logo_width;
    int waiting_logo_height;
    int waiting_logo_current_frame;
    gint64 waiting_logo_cycle_started;
    gboolean waiting_logo_enabled;
    cairo_surface_t* waiting_logo_wordmark;
    /* Decoded once at startup for both logos, then released by the waiting screen. */
    cairo_surface_t* logo_atlas;
    GdkRGBA waiting_logo_color;
    GdkRGBA status_logo_color;
    cairo_surface_t* status_logo_mask;
    GdkTexture* waiting_logo_frames[LOGO_FRAME_COUNT];
    cairo_surface_t* waiting_logo_masks[LOGO_FRAME_COUNT];
    int waiting_logo_mask_width;
    int waiting_logo_mask_height;
    gboolean waiting_logo_frames_dirty;
    gboolean proxy_auth_received;
    gboolean transport_failure;
    gboolean proxy_relay_failure;
    /* Bit i stays set until playlist view i recovers or is discarded. */
    guint proxy_content_failures;
    gboolean show_friendly_name;
    gboolean show_clock;
    gboolean show_status_logo;
    gboolean show_device_info;
    gboolean show_status_message;
    gboolean show_overlays_on_waiting;
    double webview_zoom_level;
    double banner_scale;
    double friendly_name_scale;
    double clock_scale;
    double status_logo_scale;
    double waiting_logo_scale;
    char* proxy_url;
    char* proxy_agent_id;
    char* proxy_auth_token;
    char* default_agent_name;
    char* default_agent_ip;
    char* default_tunnel_ip;
    char* default_status_stage;
    char* default_status_severity;
    char* default_status_message;
    char* custom_banner_message;
    char* custom_banner_severity;
    GMainLoop* ui_main_loop;
} RendererState;

RendererState* renderer_state(void);
void stop_timers(void);
void clear_views(void);
void schedule_playlist_retry(int index);
void playlist_record_view_failure(WebKitWebView* view, int index, gboolean failed);
void create_overlays(GtkOverlay* overlay);
void destroy_overlays(void);
void update_overlays(void);
void create_waiting_screen(void);
void update_waiting_screen(void);
void destroy_waiting_screen(void);
GtkWidget* create_status_logo(void);
void update_status_logo(void);
void logo_status_color(const char* severity, GdkRGBA* color);
cairo_surface_t* load_logo_atlas(void);
WebKitWebView* create_web_view(void);
void show_waiting_screen(void);
void playlist_view_load_changed(WebKitWebView*, WebKitLoadEvent, gpointer);
gboolean playlist_view_decide_policy(
    WebKitWebView*, WebKitPolicyDecision*, WebKitPolicyDecisionType, gpointer);
gboolean playlist_view_load_failed(
    WebKitWebView*, WebKitLoadEvent, const gchar*, GError*, gpointer);
void playlist_view_process_terminated(WebKitWebView*, WebKitWebProcessTerminationReason, gpointer);
void browser_configure_view(WebKitWebView* view);
void browser_configure_session(WebKitNetworkSession* session);
#endif
