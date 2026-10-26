/*
 * File purpose: Renders a static NeoDSE N indicating playlist connection health.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"

#define STATUS_LOGO_HEIGHT 32

/* logo_status_color gives the waiting logo and the playlist indicator one palette. */
void logo_status_color(const char* severity, GdkRGBA* color)
{
    const char* value = "#6fa5fe";
    if (g_strcmp0(severity, "success") == 0)
    {
        value = "#41c78f";
    }
    else if (g_strcmp0(severity, "warning") == 0)
    {
        value = "#eeab4e";
    }
    else if (g_strcmp0(severity, "critical") == 0)
    {
        value = "#ed6464";
    }
    gdk_rgba_parse(color, value);
}

/* load_status_logo_mask keeps only the completed N's alpha mask; the shared
 * atlas stays decoded for the waiting screen, which releases it. */
static cairo_surface_t* load_status_logo_mask(void)
{
    cairo_surface_t* atlas = load_logo_atlas();
    if (atlas == NULL)
    {
        return NULL;
    }
    cairo_surface_t* mask = cairo_image_surface_create(
        CAIRO_FORMAT_A8, LOGO_ATLAS_CELL_WIDTH, LOGO_ATLAS_CELL_HEIGHT);
    if (cairo_surface_status(mask) != CAIRO_STATUS_SUCCESS)
    {
        g_printerr("[UI] ! Cannot create status-logo mask: %s\n",
            cairo_status_to_string(cairo_surface_status(mask)));
        cairo_surface_destroy(mask);
        return NULL;
    }
    cairo_t* cr = cairo_create(mask);
    cairo_set_source_surface(cr, atlas,
        -(LOGO_COMPLETED_FRAME % LOGO_ATLAS_COLUMNS) * LOGO_ATLAS_CELL_WIDTH,
        -(LOGO_COMPLETED_FRAME / LOGO_ATLAS_COLUMNS) * LOGO_ATLAS_CELL_HEIGHT);
    cairo_paint(cr);
    cairo_destroy(cr);
    return mask;
}

/* draw_status_logo tints the cached mask with the current connection color. */
static void draw_status_logo(
    GtkDrawingArea* area, cairo_t* cr, int width, int height, gpointer user_data)
{
    (void)area;
    (void)user_data;
    RendererState* state = renderer_state();
    if (state->status_logo_mask == NULL)
    {
        return;
    }
    cairo_scale(cr, (double)width / LOGO_ATLAS_CELL_WIDTH, (double)height / LOGO_ATLAS_CELL_HEIGHT);
    cairo_set_source_rgba(cr, state->status_logo_color.red, state->status_logo_color.green,
        state->status_logo_color.blue, state->status_logo_color.alpha);
    cairo_mask_surface(cr, state->status_logo_mask, 0, 0);
}

/* create_status_logo builds a non-interactive, transparent bottom-right indicator. */
GtkWidget* create_status_logo(void)
{
    RendererState* state = renderer_state();
    GtkWidget* logo = gtk_drawing_area_new();
    gtk_widget_set_can_target(logo, FALSE);
    gtk_widget_set_halign(logo, GTK_ALIGN_END);
    gtk_widget_set_valign(logo, GTK_ALIGN_END);
    int height = (int)(STATUS_LOGO_HEIGHT * state->status_logo_scale + 0.5);
    int width = (int)((double)STATUS_LOGO_HEIGHT * LOGO_ATLAS_CELL_WIDTH / LOGO_ATLAS_CELL_HEIGHT
            * state->status_logo_scale
        + 0.5);
    int margin = (int)(24.0 * state->status_logo_scale + 0.5);
    gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(logo), width);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(logo), height);
    gtk_widget_set_margin_end(logo, margin);
    gtk_widget_set_margin_bottom(logo, margin);
    gtk_widget_set_visible(logo, FALSE);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(logo), draw_status_logo, NULL, NULL);
    if (state->show_status_logo)
    {
        state->status_logo_mask = load_status_logo_mask();
    }
    return logo;
}

/* update_status_logo sets connection color independently from banner visibility. */
void update_status_logo(void)
{
    RendererState* state = renderer_state();
    if (state->status_logo == NULL)
    {
        return;
    }
    GtkWidget* screen
        = state->stack != NULL ? gtk_stack_get_visible_child(GTK_STACK(state->stack)) : NULL;
    gboolean visible = state->show_status_logo && state->status_logo_mask != NULL && screen != NULL
        && screen != state->waiting_view;
    gtk_widget_set_visible(state->status_logo, visible);

    const char* severity = "success";
    if (state->transport_failure || state->proxy_relay_failure)
    {
        severity = "critical";
    }
    else if (state->proxy_content_failures != 0)
    {
        severity = "warning";
    }
    else if (!webview_is_ready_for_remote_content())
    {
        severity = "info";
    }
    GdkRGBA color;
    logo_status_color(severity, &color);
    if (!gdk_rgba_equal(&state->status_logo_color, &color))
    {
        state->status_logo_color = color;
        gtk_widget_queue_draw(state->status_logo);
    }
}
