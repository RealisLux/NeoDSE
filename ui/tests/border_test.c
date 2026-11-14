/*
 * File purpose: Checks border pixels, input transparency, replacement, expiry, and cleanup.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "../renderer_state.h"

static RendererState state;
static int widget;
static int waiting_marker;
static int playlist_marker;
static GtkWidget* visible_screen;
static gboolean visible;
static GtkDrawingAreaDrawFunc draw;
static GSourceFunc expiry;
static GSourceFunc flash;
static guint next_timer;
static guint removed_timer;
static guint removed_timers[64];
static guint removed_count;

RendererState* renderer_state(void) { return &state; }
GtkWidget* gtk_drawing_area_new(void) { return (GtkWidget*)&widget; }
GtkWidget* gtk_stack_get_visible_child(GtkStack* stack)
{
    (void)stack;
    return visible_screen;
}
void gtk_widget_set_can_target(GtkWidget* target, gboolean can_target)
{
    (void)target;
    g_assert_false(can_target);
}
void gtk_widget_set_visible(GtkWidget* target, gboolean value)
{
    (void)target;
    visible = value;
}
void gtk_widget_queue_draw(GtkWidget* target) { (void)target; }
void gtk_drawing_area_set_draw_func(
    GtkDrawingArea* area, GtkDrawingAreaDrawFunc callback, gpointer data, GDestroyNotify destroy)
{
    (void)area;
    (void)data;
    (void)destroy;
    draw = callback;
}
void gtk_overlay_add_overlay(GtkOverlay* overlay, GtkWidget* target)
{
    (void)overlay;
    g_assert_true(target == state.border);
}
guint __wrap_g_timeout_add_seconds(guint interval, GSourceFunc function, gpointer data)
{
    (void)data;
    g_assert_cmpuint(interval, >=, 1);
    g_assert_cmpuint(interval, <=, 300);
    expiry = function;
    return ++next_timer;
}
guint __wrap_g_timeout_add(guint interval, GSourceFunc function, gpointer data)
{
    (void)data;
    g_assert_cmpuint(interval, ==, 500);
    flash = function;
    return ++next_timer;
}
gboolean __wrap_g_source_remove(guint tag)
{
    removed_timer = tag;
    g_assert_cmpuint(removed_count, <, G_N_ELEMENTS(removed_timers));
    removed_timers[removed_count++] = tag;
    return TRUE;
}

static gboolean was_removed(guint tag)
{
    for (guint i = 0; i < removed_count; i++)
    {
        if (removed_timers[i] == tag)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* assert_pixels checks all four edges and the transparent page interior. */
static void assert_pixels(int width, int height, guint32 color)
{
    cairo_surface_t* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cairo_t* cr = cairo_create(surface);
    draw(NULL, cr, width, height, NULL);
    cairo_destroy(cr);
    cairo_surface_flush(surface);
    guint32* pixels = (guint32*)cairo_image_surface_get_data(surface);
    int stride = cairo_image_surface_get_stride(surface) / (int)sizeof(guint32);
    for (int y = 0; y < height; y++)
    {
        for (int x = 0; x < width; x++)
        {
            gboolean edge = x < state.border_width || x >= width - state.border_width
                || y < state.border_width || y >= height - state.border_width;
            g_assert_cmphex(pixels[y * stride + x], ==, edge ? color : 0);
        }
    }
    cairo_surface_destroy(surface);
}

static void test_border_lifecycle(void)
{
    g_unsetenv("NEODSE_BORDER_WIDTH");
    g_unsetenv("NEODSE_BORDER_FLASH");
    create_border(NULL);
    g_assert_false(visible);
    g_assert_cmpint(state.border_width, ==, 6);
    g_assert_false(state.border_flash_enabled);
    webview_show_border("info", 1);
    g_assert_true(visible);
    g_assert_cmpuint(state.border_flash_timer, ==, 0);
    assert_pixels(100, 80, 0xff1565c0);
    guint old_timer = state.border_timer;
    webview_show_border("warning", 300);
    g_assert_cmpuint(removed_timer, ==, old_timer);
    assert_pixels(120, 90, 0xffef6c00);
    webview_show_border("critical", 30);
    assert_pixels(100, 80, 0xffc62828);
    g_assert_cmpint(expiry(NULL), ==, G_SOURCE_REMOVE);
    g_assert_false(visible);
    g_assert_cmpuint(state.border_timer, ==, 0);
    webview_show_border("info", 1);
    old_timer = state.border_timer;
    destroy_border();
    g_assert_cmpuint(removed_timer, ==, old_timer);
    g_assert_cmpuint(state.border_timer, ==, 0);
}

/* test_waiting_visibility follows the banner gate without restarting the timer. */
static void test_waiting_visibility(void)
{
    create_border(NULL);
    visible_screen = state.waiting_view;
    webview_show_border("warning", 30);
    guint original_timer = state.border_timer;
    g_assert_false(visible);
    visible_screen = (GtkWidget*)&playlist_marker;
    update_border();
    g_assert_true(visible);
    g_assert_cmpuint(state.border_timer, ==, original_timer);
    visible_screen = state.waiting_view;
    update_border();
    g_assert_false(visible);
    state.show_overlays_on_waiting = TRUE;
    update_border();
    g_assert_true(visible);
    g_assert_cmpuint(state.border_timer, ==, original_timer);
    state.show_overlays_on_waiting = FALSE;
    update_border();
    g_assert_false(visible);
    g_assert_cmpint(expiry(NULL), ==, G_SOURCE_REMOVE);
    visible_screen = (GtkWidget*)&playlist_marker;
    update_border();
    g_assert_false(visible);
    g_assert_cmpuint(state.border_timer, ==, 0);
}

/* test_flashing checks phase, replacement, waiting visibility, expiry and teardown. */
static void test_flashing(void)
{
    g_setenv("NEODSE_BORDER_FLASH", "on", TRUE);
    create_border(NULL);
    g_unsetenv("NEODSE_BORDER_FLASH");
    g_assert_true(state.border_flash_enabled);
    webview_show_border("warning", 30);
    g_assert_true(visible);
    guint original_expiry = state.border_timer;
    guint original_flash = state.border_flash_timer;
    g_assert_cmpuint(original_flash, !=, 0);
    g_assert_cmpint(flash(NULL), ==, G_SOURCE_CONTINUE);
    g_assert_false(visible);
    update_border();
    g_assert_false(visible);
    g_assert_cmpuint(state.border_timer, ==, original_expiry);
    visible_screen = state.waiting_view;
    g_assert_cmpint(flash(NULL), ==, G_SOURCE_CONTINUE);
    g_assert_false(visible);
    state.show_overlays_on_waiting = TRUE;
    update_border();
    g_assert_true(visible);
    g_assert_cmpint(flash(NULL), ==, G_SOURCE_CONTINUE);
    g_assert_false(visible);
    state.show_overlays_on_waiting = FALSE;
    visible_screen = (GtkWidget*)&playlist_marker;
    webview_show_border("critical", 60);
    g_assert_true(visible);
    assert_pixels(100, 80, 0xffc62828);
    g_assert_true(was_removed(original_expiry));
    g_assert_true(was_removed(original_flash));
    g_assert_cmpuint(state.border_timer, !=, original_expiry);
    g_assert_cmpuint(state.border_flash_timer, !=, original_flash);
    original_flash = state.border_flash_timer;
    g_assert_cmpint(expiry(NULL), ==, G_SOURCE_REMOVE);
    g_assert_false(visible);
    g_assert_cmpuint(state.border_timer, ==, 0);
    g_assert_cmpuint(state.border_flash_timer, ==, 0);
    g_assert_true(was_removed(original_flash));
    webview_show_border("info", 30);
    original_expiry = state.border_timer;
    original_flash = state.border_flash_timer;
    destroy_border();
    g_assert_cmpuint(state.border_timer, ==, 0);
    g_assert_cmpuint(state.border_flash_timer, ==, 0);
    g_assert_true(was_removed(original_expiry));
    g_assert_true(was_removed(original_flash));
}

static void test_flash_setting(void)
{
    const char* invalid[] = { "", "yes", "true", "1", "show", "ON" };
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++)
    {
        g_setenv("NEODSE_BORDER_FLASH", invalid[i], TRUE);
        create_border(NULL);
        g_assert_false(state.border_flash_enabled);
    }
    g_setenv("NEODSE_BORDER_FLASH", "on", TRUE);
    create_border(NULL);
    g_assert_true(state.border_flash_enabled);
    g_setenv("NEODSE_BORDER_FLASH", "off", TRUE);
    create_border(NULL);
    g_assert_false(state.border_flash_enabled);
    webview_show_border("info", 1);
    g_assert_true(visible);
    g_assert_cmpuint(state.border_flash_timer, ==, 0);
    destroy_border();
    g_unsetenv("NEODSE_BORDER_FLASH");
}

static void test_border_width(void)
{
    const char* invalid[] = { "", "0", "65", "-1", "2.5", "12px", "99999999999999999999" };
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++)
    {
        g_setenv("NEODSE_BORDER_WIDTH", invalid[i], TRUE);
        create_border(NULL);
        g_assert_cmpint(state.border_width, ==, 6);
    }
    g_setenv("NEODSE_BORDER_WIDTH", "4", TRUE);
    create_border(NULL);
    g_assert_cmpint(state.border_width, ==, 4);
    webview_show_border("critical", 1);
    assert_pixels(100, 80, 0xffc62828);
    destroy_border();
    g_unsetenv("NEODSE_BORDER_WIDTH");
}

int main(int argc, char** argv)
{
    g_test_init(&argc, &argv, NULL);
    state.stack = (GtkWidget*)&widget;
    state.waiting_view = (GtkWidget*)&waiting_marker;
    visible_screen = (GtkWidget*)&playlist_marker;
    g_test_add_func("/border/lifecycle", test_border_lifecycle);
    g_test_add_func("/border/waiting-visibility", test_waiting_visibility);
    g_test_add_func("/border/flashing", test_flashing);
    g_test_add_func("/border/flash-setting", test_flash_setting);
    g_test_add_func("/border/width", test_border_width);
    return g_test_run();
}
