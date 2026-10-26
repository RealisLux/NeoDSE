/*
 * File purpose: Builds persistent corner overlays and manages custom-message banners.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"
#include "validation.h"

/* configure_overlays reads overlay scales and visibility before widgets are built. */
static void configure_overlays(void)
{
    RendererState* state = renderer_state();
    state->banner_scale = neodse_env_scale("NEODSE_BANNER_SCALE", state->banner_scale);
    state->friendly_name_scale
        = neodse_env_scale("NEODSE_FRIENDLY_NAME_SCALE", state->friendly_name_scale);
    state->show_clock = neodse_env_visibility("NEODSE_UI_CLOCK", TRUE);
    state->clock_scale = neodse_env_scale("NEODSE_CLOCK_SCALE", state->clock_scale);
    /* The display name is shown by default when one is configured. */
    state->show_friendly_name = neodse_env_visibility("NEODSE_UI_FRIENDLY_NAME", TRUE);
    /* Banners, display name and clock are hidden on the waiting screen by default. */
    state->show_overlays_on_waiting = neodse_env_visibility("NEODSE_UI_WAITING_OVERLAYS", FALSE);
}

/* update_clock reads wall-clock time so timezone and system-time changes are reflected. */
static gboolean update_clock(gpointer user_data)
{
    (void)user_data;
    GDateTime* now = g_date_time_new_now_local();
    if (now != NULL)
    {
        char* time = g_date_time_format(now, "%H:%M:%S");
        gtk_label_set_text(GTK_LABEL(renderer_state()->clock), time);
        g_free(time);
        g_date_time_unref(now);
    }
    return G_SOURCE_CONTINUE;
}

/* visible_screen_changed re-evaluates overlay visibility when the stack changes screen. */
static void visible_screen_changed(GObject* stack, GParamSpec* property, gpointer user_data)
{
    (void)stack;
    (void)property;
    (void)user_data;
    update_overlays();
}

/* scaled_banner_size applies the banner-specific scale to the native GTK
 * overlay independently from WebKit content. */
static int scaled_banner_size(int base_size)
{
    return (int)((double)base_size * renderer_state()->banner_scale + 0.5);
}

/* set_banner_visibility applies the waiting-screen gate independently to the
 * banner and persistent corner overlays. Their shared layout prevents overlap. */
static void set_banner_visibility(gboolean visible)
{
    RendererState* state = renderer_state();
    GtkWidget* screen
        = state->stack != NULL ? gtk_stack_get_visible_child(GTK_STACK(state->stack)) : NULL;
    gboolean show_overlays = state->show_overlays_on_waiting || screen != state->waiting_view;
    visible = visible && show_overlays;
    gtk_widget_set_visible(state->notification_banner, visible);
    gboolean has_corner_overlay = FALSE;
    if (state->clock != NULL)
    {
        gboolean show_clock = show_overlays && state->show_clock;
        gtk_widget_set_visible(state->clock, show_clock);
        has_corner_overlay = show_clock;
    }
    if (state->friendly_name != NULL)
    {
        const char* friendly_name = gtk_label_get_text(GTK_LABEL(state->friendly_name));
        gboolean show_name = show_overlays && state->show_friendly_name && friendly_name != NULL
            && friendly_name[0] != '\0';
        gtk_widget_set_visible(state->friendly_name, show_name);
        has_corner_overlay = has_corner_overlay || show_name;
    }
    gtk_widget_set_margin_top(
        state->notification_banner, scaled_banner_size(has_corner_overlay ? 12 : 24));
}

/* update_overlays refreshes the status N and custom-message overlay visibility. */
void update_overlays(void)
{
    if (renderer_state()->notification_banner == NULL || renderer_state()->banner_label == NULL)
    {
        return;
    }

    update_status_logo();
    GtkWidget* visible = renderer_state()->stack != NULL
        ? gtk_stack_get_visible_child(GTK_STACK(renderer_state()->stack))
        : NULL;
    if (!renderer_state()->show_overlays_on_waiting && visible == renderer_state()->waiting_view)
    {
        set_banner_visibility(FALSE);
        return;
    }

    const char* message = renderer_state()->custom_banner_message;
    const char* severity = renderer_state()->custom_banner_severity;

    if (message == NULL)
    {
        set_banner_visibility(FALSE);
        return;
    }

    gtk_label_set_text(GTK_LABEL(renderer_state()->banner_label), message);
    gtk_widget_remove_css_class(renderer_state()->notification_banner, "banner-info");
    gtk_widget_remove_css_class(renderer_state()->notification_banner, "banner-warning");
    gtk_widget_remove_css_class(renderer_state()->notification_banner, "banner-critical");
    if (g_strcmp0(severity, "warning") == 0)
    {
        gtk_widget_add_css_class(renderer_state()->notification_banner, "banner-warning");
    }
    else if (g_strcmp0(severity, "critical") == 0)
    {
        gtk_widget_add_css_class(renderer_state()->notification_banner, "banner-critical");
    }
    else
    {
        gtk_widget_add_css_class(renderer_state()->notification_banner, "banner-info");
    }
    set_banner_visibility(TRUE);
}

/* create_notification_banner builds the custom-message overlay above WebKit content. */
static GtkWidget* create_notification_banner(void)
{
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, scaled_banner_size(12));
    renderer_state()->banner_icon = gtk_image_new_from_icon_name("dialog-information-symbolic");
    renderer_state()->banner_label = gtk_label_new("");

    gtk_image_set_pixel_size(GTK_IMAGE(renderer_state()->banner_icon), scaled_banner_size(24));
    /* Keep messages on one line, truncating them within the screen margins. */
    gtk_label_set_single_line_mode(GTK_LABEL(renderer_state()->banner_label), TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(renderer_state()->banner_label), PANGO_ELLIPSIZE_END);
    gtk_label_set_justify(GTK_LABEL(renderer_state()->banner_label), GTK_JUSTIFY_CENTER);
    gtk_widget_add_css_class(box, "notification-banner");
    gtk_box_append(GTK_BOX(box), renderer_state()->banner_icon);
    gtk_box_append(GTK_BOX(box), renderer_state()->banner_label);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_START);
    gtk_widget_set_margin_top(box, scaled_banner_size(24));
    gtk_widget_set_margin_start(box, scaled_banner_size(24));
    gtk_widget_set_margin_end(box, scaled_banner_size(24));
    gtk_widget_set_visible(box, FALSE);

    GtkCssProvider* provider = gtk_css_provider_new();
    char* css = g_strdup_printf(".notification-banner {"
                                " color: white;"
                                " border: %dpx solid rgba(255, 255, 255, 0.28);"
                                " border-radius: %dpx;"
                                " padding: %dpx %dpx;"
                                " box-shadow: 0 %dpx %dpx rgba(0, 0, 0, 0.35);"
                                " font-size: %dpx;"
                                " font-weight: 700;"
                                "}"
                                ".banner-info { background: rgba(21, 101, 192, 0.96); }"
                                ".banner-warning { background: rgba(239, 108, 0, 0.97); }"
                                ".banner-critical { background: rgba(198, 40, 40, 0.96); }",
        scaled_banner_size(1), scaled_banner_size(14), scaled_banner_size(14),
        scaled_banner_size(22), scaled_banner_size(8), scaled_banner_size(28),
        scaled_banner_size(18));
    gtk_css_provider_load_from_string(provider, css);
    g_free(css);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);

    return box;
}

/* expire_custom_banner clears the active message when its original duration
 * elapses. */
static gboolean expire_custom_banner(gpointer user_data)
{
    (void)user_data;
    renderer_state()->custom_banner_timer = 0;
    g_clear_pointer(&renderer_state()->custom_banner_message, g_free);
    g_clear_pointer(&renderer_state()->custom_banner_severity, g_free);
    update_overlays();
    return G_SOURCE_REMOVE;
}

/* webview_show_banner replaces the active message and timer on the GTK thread.
 */
void webview_show_banner(const char* message, const char* severity, guint duration_seconds)
{
    if (renderer_state()->custom_banner_timer != 0)
    {
        g_source_remove(renderer_state()->custom_banner_timer);
    }
    g_free(renderer_state()->custom_banner_message);
    g_free(renderer_state()->custom_banner_severity);
    renderer_state()->custom_banner_message = g_strdup(message);
    renderer_state()->custom_banner_severity = g_strdup(severity);
    renderer_state()->custom_banner_timer
        = g_timeout_add_seconds(duration_seconds, expire_custom_banner, NULL);
    update_overlays();
}

/* create_overlays builds the custom banner, display name and clock once. */
void create_overlays(GtkOverlay* overlay)
{
    configure_overlays();

    /* GTK measures the corner row at the taller visible label's actual height,
     * including its scaled font and padding. The banner then flows below it,
     * even when text, visibility, scale or available width changes. */
    GtkWidget* top_overlays = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget* corners = gtk_overlay_new();
    gtk_widget_set_valign(top_overlays, GTK_ALIGN_START);
    gtk_widget_set_can_target(top_overlays, FALSE);
    gtk_overlay_add_overlay(overlay, top_overlays);
    gtk_box_append(GTK_BOX(top_overlays), corners);
    renderer_state()->notification_banner = create_notification_banner();
    gtk_widget_set_can_target(renderer_state()->notification_banner, FALSE);
    gtk_box_append(GTK_BOX(top_overlays), renderer_state()->notification_banner);
    renderer_state()->friendly_name = gtk_label_new("");
    gtk_widget_set_can_target(renderer_state()->friendly_name, FALSE);
    gtk_widget_add_css_class(renderer_state()->friendly_name, "friendly-name");
    gtk_widget_set_halign(renderer_state()->friendly_name, GTK_ALIGN_START);
    gtk_widget_set_valign(renderer_state()->friendly_name, GTK_ALIGN_START);
    int friendly_margin = (int)(24.0 * renderer_state()->friendly_name_scale + 0.5);
    gtk_widget_set_margin_start(renderer_state()->friendly_name, friendly_margin);
    gtk_label_set_ellipsize(GTK_LABEL(renderer_state()->friendly_name), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(renderer_state()->friendly_name), 48);
    gtk_widget_set_visible(renderer_state()->friendly_name, FALSE);
    gtk_overlay_add_overlay(GTK_OVERLAY(corners), renderer_state()->friendly_name);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(corners), renderer_state()->friendly_name, TRUE);
    renderer_state()->clock = gtk_label_new("");
    gtk_widget_set_can_target(renderer_state()->clock, FALSE);
    gtk_widget_add_css_class(renderer_state()->clock, "clock");
    gtk_widget_set_halign(renderer_state()->clock, GTK_ALIGN_END);
    gtk_widget_set_valign(renderer_state()->clock, GTK_ALIGN_START);
    int clock_margin = (int)(24.0 * renderer_state()->clock_scale + 0.5);
    gtk_widget_set_margin_end(renderer_state()->clock, clock_margin);
    gtk_widget_set_visible(renderer_state()->clock, renderer_state()->show_clock);
    gtk_overlay_add_overlay(GTK_OVERLAY(corners), renderer_state()->clock);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(corners), renderer_state()->clock, TRUE);
    if (renderer_state()->show_clock)
    {
        update_clock(NULL);
        renderer_state()->clock_timer = g_timeout_add_seconds(1, update_clock, NULL);
    }
    GtkCssProvider* provider = gtk_css_provider_new();
    char* styles = g_strdup_printf(
        ".friendly-name, .clock { color: white; background: #000;"
        " border-radius: 0; font-weight: 700; }"
        " .friendly-name { padding: %dpx %dpx; font-size: %dpx; }"
        " .clock { padding: %dpx %dpx; font-size: %dpx; font-family: monospace; }",
        (int)(8.0 * renderer_state()->friendly_name_scale + 0.5),
        (int)(12.0 * renderer_state()->friendly_name_scale + 0.5),
        (int)(18.0 * renderer_state()->friendly_name_scale + 0.5),
        (int)(8.0 * renderer_state()->clock_scale + 0.5),
        (int)(12.0 * renderer_state()->clock_scale + 0.5),
        (int)(18.0 * renderer_state()->clock_scale + 0.5));
    gtk_css_provider_load_from_string(provider, styles);
    g_free(styles);
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
    g_signal_connect(
        renderer_state()->stack, "notify::visible-child", G_CALLBACK(visible_screen_changed), NULL);
}

/* destroy_overlays releases timers and cached custom messages before window teardown. */
void destroy_overlays(void)
{
    if (renderer_state()->clock_timer != 0)
    {
        g_source_remove(renderer_state()->clock_timer);
        renderer_state()->clock_timer = 0;
    }
    if (renderer_state()->custom_banner_timer != 0)
    {
        g_source_remove(renderer_state()->custom_banner_timer);
        renderer_state()->custom_banner_timer = 0;
    }
    g_clear_pointer(&renderer_state()->custom_banner_message, g_free);
    g_clear_pointer(&renderer_state()->custom_banner_severity, g_free);
}
