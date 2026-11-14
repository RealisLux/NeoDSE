/*
 * File purpose: Draws a configurable, input-transparent screen border above WebKit.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"

#define BORDER_FLASH_INTERVAL_MS 500

/* draw_border fills only the screen edges, leaving content geometry unchanged. */
static void draw_border(
    GtkDrawingArea* area, cairo_t* cr, int width, int height, gpointer user_data)
{
    (void)area;
    (void)user_data;
    RendererState* state = renderer_state();
    double inset = MIN(state->border_width, MIN(width, height) / 2.0);
    cairo_set_source_rgba(cr, state->border_color.red, state->border_color.green,
        state->border_color.blue, state->border_color.alpha);
    cairo_rectangle(cr, 0, 0, width, height);
    cairo_rectangle(cr, inset, inset, width - 2 * inset, height - 2 * inset);
    cairo_set_fill_rule(cr, CAIRO_FILL_RULE_EVEN_ODD);
    cairo_fill(cr);
}

/* create_border reads local appearance settings once at UI startup. */
void create_border(GtkOverlay* overlay)
{
    RendererState* state = renderer_state();
    state->border_width = 6;
    const char* configured = g_getenv("NEODSE_BORDER_WIDTH");
    if (configured != NULL)
    {
        char* end = NULL;
        gint64 width = g_ascii_strtoll(configured, &end, 10);
        if (end != configured && *end == '\0' && width >= 1 && width <= 64)
        {
            state->border_width = (int)width;
        }
        else
        {
            g_printerr("[UI] ! Invalid NEODSE_BORDER_WIDTH; using default\n");
        }
    }
    configured = g_getenv("NEODSE_BORDER_FLASH");
    state->border_flash_enabled = g_strcmp0(configured, "on") == 0;
    if (configured != NULL && g_strcmp0(configured, "off") != 0 && !state->border_flash_enabled)
    {
        g_printerr("[UI] ! Invalid NEODSE_BORDER_FLASH; using off\n");
    }
    state->border_flash_visible = TRUE;
    state->border = gtk_drawing_area_new();
    gtk_widget_set_can_target(state->border, FALSE);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(state->border), draw_border, NULL, NULL);
    gtk_widget_set_visible(state->border, FALSE);
    gtk_overlay_add_overlay(overlay, state->border);
}

/* update_border applies the same waiting-screen gate as the banner. */
void update_border(void)
{
    RendererState* state = renderer_state();
    if (state->border == NULL)
    {
        return;
    }
    GtkWidget* screen
        = state->stack != NULL ? gtk_stack_get_visible_child(GTK_STACK(state->stack)) : NULL;
    gboolean show_overlays = state->show_overlays_on_waiting || screen != state->waiting_view;
    gboolean lit = !state->border_flash_enabled || state->border_flash_visible;
    gtk_widget_set_visible(state->border, state->border_timer != 0 && show_overlays && lit);
}

/* flash_border toggles visibility without changing the request's expiry. */
static gboolean flash_border(gpointer user_data)
{
    (void)user_data;
    renderer_state()->border_flash_visible = !renderer_state()->border_flash_visible;
    update_border();
    return G_SOURCE_CONTINUE;
}

/* expire_border hides the highlight without disturbing other overlays. */
static gboolean expire_border(gpointer user_data)
{
    (void)user_data;
    renderer_state()->border_timer = 0;
    destroy_border();
    update_border();
    return G_SOURCE_REMOVE;
}

/* destroy_border removes both sources before replacement or renderer teardown. */
void destroy_border(void)
{
    if (renderer_state()->border_timer != 0)
    {
        g_source_remove(renderer_state()->border_timer);
        renderer_state()->border_timer = 0;
    }
    if (renderer_state()->border_flash_timer != 0)
    {
        g_source_remove(renderer_state()->border_flash_timer);
        renderer_state()->border_flash_timer = 0;
    }
    renderer_state()->border_flash_visible = TRUE;
}

/* webview_show_border replaces both the color and expiry on the GTK owner thread. */
void webview_show_border(const char* severity, guint duration_seconds)
{
    RendererState* state = renderer_state();
    destroy_border();
    /* Match the banner palette: info blue, warning orange, critical red. */
    const char* color = "#1565c0";
    if (g_strcmp0(severity, "critical") == 0)
    {
        color = "#c62828";
    }
    else if (g_strcmp0(severity, "warning") == 0)
    {
        color = "#ef6c00";
    }
    gdk_rgba_parse(&state->border_color, color);
    gtk_widget_queue_draw(state->border);
    state->border_timer = g_timeout_add_seconds(duration_seconds, expire_border, NULL);
    if (state->border_flash_enabled)
    {
        state->border_flash_timer = g_timeout_add(BORDER_FLASH_INTERVAL_MS, flash_border, NULL);
    }
    update_border();
}
