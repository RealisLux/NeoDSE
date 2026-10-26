/*
 * File purpose: Builds the native waiting screen and manages its logo animation and status.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"
#include "validation.h"

/* NEODSE_WAITING_LOGO_SCALE at which the logo has its native size. */
#define LOGO_NATIVE_SCALE 3.0
#define LOGO_NATIVE_WIDTH 2048
#define LOGO_NATIVE_HEIGHT 682
/* Frames 60-74 dissolve the completed N through all 15 levels of a 4x4 dither. */
#define LOGO_FADE_FRAMES 15
#define LOGO_ANIMATION_US (3320000 + LOGO_FADE_FRAMES * 40000 + 800000)
/* Position of the animated cell over the wordmark at native size. */
#define LOGO_ATLAS_CELL_X 40
#define LOGO_ATLAS_CELL_Y 100

/* configure_waiting_screen reads waiting-logo and waiting-text settings. */
static void configure_waiting_screen(void)
{
    RendererState* state = renderer_state();
    state->waiting_logo_scale
        = neodse_env_scale("NEODSE_WAITING_LOGO_SCALE", state->waiting_logo_scale);
    /* Hiding the animation leaves the completed N visible. */
    state->waiting_logo_enabled = neodse_env_visibility("NEODSE_UI_LOGO_ANIMATION", TRUE);
    /* Device identifiers and status text are opt-in. */
    state->show_device_info = neodse_env_visibility("NEODSE_UI_DEVICE_INFO", FALSE);
    state->show_status_message = neodse_env_visibility("NEODSE_UI_STATUS_MESSAGE", FALSE);
}

/* waiting_logo_frame_for_elapsed selects the atlas frame for a time in its loop. */
static int waiting_logo_frame_for_elapsed(gint64 elapsed_us)
{
    gint64 elapsed_ms = (elapsed_us % LOGO_ANIMATION_US) / 1000;
    if (elapsed_ms < 160)
    {
        return 0;
    }
    elapsed_ms -= 160;
    if (elapsed_ms < 2320)
    {
        return 1 + (int)(elapsed_ms / 40);
    }
    elapsed_ms -= 2320;
    if (elapsed_ms < 840)
    {
        return LOGO_COMPLETED_FRAME;
    }
    elapsed_ms -= 840;
    if (elapsed_ms < LOGO_FADE_FRAMES * 40)
    {
        return 60 + (int)(elapsed_ms / 40);
    }
    return LOGO_FRAME_COUNT - 1;
}

/* draw_waiting_wordmark paints the static wordmark inside the fitted logo bounds. */
static void draw_waiting_wordmark(
    GtkDrawingArea* area, cairo_t* cr, int width, int height, gpointer user_data)
{
    (void)area;
    (void)user_data;

    cairo_surface_t* wordmark = renderer_state()->waiting_logo_wordmark;
    if (wordmark == NULL)
    {
        return;
    }
    cairo_scale(cr, (double)width / LOGO_NATIVE_WIDTH, (double)height / LOGO_NATIVE_HEIGHT);
    cairo_set_source_surface(cr, wordmark, 0.0, 0.0);
    cairo_paint(cr);
}

static void cache_waiting_logo_frames(void);

/* animate_waiting_logo presents cached textures and wakes only at the next frame boundary. */
static gboolean animate_waiting_logo(gpointer user_data)
{
    (void)user_data;
    RendererState* state = renderer_state();
    state->waiting_logo_timer = 0;
    GtkWidget* logo = state->waiting_logo_animation;
    if (logo == NULL || !gtk_widget_get_mapped(logo))
    {
        return G_SOURCE_REMOVE;
    }
    /* Mapping precedes the first allocation; build frames once the logo fits. */
    if (state->waiting_logo_width == 0)
    {
        return G_SOURCE_REMOVE;
    }
    if (state->waiting_logo_frames_dirty)
    {
        cache_waiting_logo_frames();
    }
    if (state->waiting_logo_frames[0] == NULL)
    {
        return G_SOURCE_REMOVE;
    }

    gboolean enabled = TRUE;
    g_object_get(gtk_widget_get_settings(logo), "gtk-enable-animations", &enabled, NULL);
    gint64 elapsed
        = (g_get_monotonic_time() - state->waiting_logo_cycle_started) % LOGO_ANIMATION_US;
    enabled = enabled && state->waiting_logo_enabled;
    int frame = enabled ? waiting_logo_frame_for_elapsed(elapsed) : LOGO_COMPLETED_FRAME;
    if (gtk_picture_get_paintable(GTK_PICTURE(logo))
        != GDK_PAINTABLE(state->waiting_logo_frames[frame]))
    {
        gtk_picture_set_paintable(
            GTK_PICTURE(logo), GDK_PAINTABLE(state->waiting_logo_frames[frame]));
    }
    state->waiting_logo_current_frame = frame;
    if (enabled)
    {
        gint64 next = frame == 0            ? 160000
            : frame < LOGO_COMPLETED_FRAME  ? 160000 + frame * 40000
            : frame == LOGO_COMPLETED_FRAME ? 3320000
            : frame < LOGO_FRAME_COUNT - 1  ? 3320000 + (frame - LOGO_COMPLETED_FRAME) * 40000
                                            : LOGO_ANIMATION_US;
        guint delay_ms = (guint)((next - elapsed + 999) / 1000);
        state->waiting_logo_timer = g_timeout_add(delay_ms, animate_waiting_logo, NULL);
    }
    return G_SOURCE_REMOVE;
}

/* refresh_waiting_logo replaces any pending frame timer with an immediate update. */
static void refresh_waiting_logo(void)
{
    RendererState* state = renderer_state();
    if (state->waiting_logo_timer != 0)
    {
        g_source_remove(state->waiting_logo_timer);
        state->waiting_logo_timer = 0;
    }
    animate_waiting_logo(NULL);
}

/* waiting_logo_mapping_changed starts or stops the animation with visibility. */
static void waiting_logo_mapping_changed(GtkWidget* widget, gpointer user_data)
{
    (void)widget;
    (void)user_data;
    refresh_waiting_logo();
}

/* waiting_logo_settings_changed follows GTK's animation preference. */
static void waiting_logo_settings_changed(
    GObject* settings, GParamSpec* property, gpointer user_data)
{
    (void)settings;
    (void)property;
    (void)user_data;
    refresh_waiting_logo();
}

/* load_logo_atlas decodes the large source atlas once until the waiting
 * screen releases it. */
cairo_surface_t* load_logo_atlas(void)
{
    RendererState* state = renderer_state();
    if (state->logo_atlas != NULL)
    {
        return state->logo_atlas;
    }
    cairo_surface_t* atlas = cairo_image_surface_create_from_png(LOGO_ATLAS_PATH);
    if (cairo_surface_status(atlas) != CAIRO_STATUS_SUCCESS)
    {
        g_printerr("[UI] ! Cannot load logo atlas: %s\n",
            cairo_status_to_string(cairo_surface_status(atlas)));
        cairo_surface_destroy(atlas);
        return NULL;
    }
    state->logo_atlas = atlas;
    return atlas;
}

/* cache_waiting_logo_masks keeps only display-sized alpha masks and releases the atlas. */
static gboolean cache_waiting_logo_masks(int width, int height)
{
    RendererState* state = renderer_state();
    if (state->waiting_logo_mask_width == width && state->waiting_logo_mask_height == height)
    {
        return TRUE;
    }
    cairo_surface_t* atlas = load_logo_atlas();
    if (atlas == NULL)
    {
        return FALSE;
    }
    for (int frame = 0; frame < LOGO_FRAME_COUNT; frame++)
    {
        cairo_surface_t* mask = cairo_image_surface_create(CAIRO_FORMAT_A8, width, height);
        if (cairo_surface_status(mask) != CAIRO_STATUS_SUCCESS)
        {
            cairo_surface_destroy(mask);
            return FALSE;
        }
        cairo_t* cr = cairo_create(mask);
        cairo_scale(
            cr, (double)width / LOGO_ATLAS_CELL_WIDTH, (double)height / LOGO_ATLAS_CELL_HEIGHT);
        cairo_set_source_surface(cr, atlas, -(frame % LOGO_ATLAS_COLUMNS) * LOGO_ATLAS_CELL_WIDTH,
            -(frame / LOGO_ATLAS_COLUMNS) * LOGO_ATLAS_CELL_HEIGHT);
        cairo_paint(cr);
        cairo_destroy(cr);
        if (state->waiting_logo_masks[frame] != NULL)
        {
            cairo_surface_destroy(state->waiting_logo_masks[frame]);
        }
        state->waiting_logo_masks[frame] = mask;
    }
    g_clear_pointer(&state->logo_atlas, cairo_surface_destroy);
    state->waiting_logo_mask_width = width;
    state->waiting_logo_mask_height = height;
    state->waiting_logo_frames_dirty = TRUE;
    return TRUE;
}

/* cache_waiting_logo_frames tints the small masks when needed, without copying pixels. */
static void cache_waiting_logo_frames(void)
{
    RendererState* state = renderer_state();
    int width, height;
    gtk_widget_get_size_request(state->waiting_logo_animation, &width, &height);
    int scale = gtk_widget_get_scale_factor(state->waiting_logo_animation);
    width *= scale;
    height *= scale;
    if (!cache_waiting_logo_masks(width, height) || !state->waiting_logo_frames_dirty)
    {
        return;
    }
    for (int frame = 0; frame < LOGO_FRAME_COUNT; frame++)
    {
        cairo_surface_t* surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
        if (cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS)
        {
            cairo_surface_destroy(surface);
            return;
        }
        cairo_t* cr = cairo_create(surface);
        cairo_set_source_rgba(cr, state->waiting_logo_color.red, state->waiting_logo_color.green,
            state->waiting_logo_color.blue, state->waiting_logo_color.alpha);
        cairo_mask_surface(cr, state->waiting_logo_masks[frame], 0, 0);
        cairo_destroy(cr);
        cairo_surface_flush(surface);
        int stride = cairo_image_surface_get_stride(surface);
        GBytes* bytes = g_bytes_new_with_free_func(cairo_image_surface_get_data(surface),
            (gsize)stride * height, (GDestroyNotify)cairo_surface_destroy, surface);
        g_clear_object(&state->waiting_logo_frames[frame]);
        state->waiting_logo_frames[frame]
            = gdk_memory_texture_new(width, height, GDK_MEMORY_DEFAULT, bytes, stride);
        g_bytes_unref(bytes);
    }
    state->waiting_logo_frames_dirty = FALSE;
}

/* waiting_logo_scale_changed rebuilds frames for a new output scale. */
static void waiting_logo_scale_changed(GObject* logo, GParamSpec* property, gpointer user_data)
{
    (void)logo;
    (void)property;
    (void)user_data;
    renderer_state()->waiting_logo_frames_dirty = TRUE;
    refresh_waiting_logo();
}

/* fit_waiting_logo shrinks the configured logo to the screen: a fullscreen window
 * wider or taller than its output is a protocol error that makes Weston drop the renderer. */
static void fit_waiting_logo(GtkDrawingArea* screen, int width, int height, gpointer user_data)
{
    (void)screen;
    (void)user_data;
    RendererState* state = renderer_state();
    double logo_width = LOGO_NATIVE_WIDTH * state->waiting_logo_scale / LOGO_NATIVE_SCALE;
    double logo_height = LOGO_NATIVE_HEIGHT * state->waiting_logo_scale / LOGO_NATIVE_SCALE;
    double fit = MIN(1.0, MIN(width / logo_width, height / logo_height));
    int fitted_width = fit < 1.0 ? (int)(logo_width * fit) : (int)(logo_width + 0.5);
    int fitted_height = fit < 1.0 ? (int)(logo_height * fit) : (int)(logo_height + 0.5);
    if (fitted_width < 1 || fitted_height < 1
        || (fitted_width == state->waiting_logo_width
            && fitted_height == state->waiting_logo_height))
    {
        return;
    }
    if (fit < 1.0)
    {
        g_print("[UI] Waiting logo reduced to %dx%d for the %dx%d screen\n", fitted_width,
            fitted_height, width, height);
    }
    state->waiting_logo_width = fitted_width;
    state->waiting_logo_height = fitted_height;
    gtk_widget_set_size_request(state->waiting_logo, fitted_width, fitted_height);
    GtkDrawingArea* wordmark = GTK_DRAWING_AREA(state->waiting_logo_wordmark_area);
    gtk_drawing_area_set_content_width(wordmark, fitted_width);
    gtk_drawing_area_set_content_height(wordmark, fitted_height);
    double logo_factor = (double)fitted_width / LOGO_NATIVE_WIDTH;
    gtk_widget_set_size_request(state->waiting_logo_animation,
        MAX(1, (int)(LOGO_ATLAS_CELL_WIDTH * logo_factor + 0.5)),
        MAX(1, (int)(LOGO_ATLAS_CELL_HEIGHT * logo_factor + 0.5)));
    gtk_fixed_move(GTK_FIXED(state->waiting_logo), state->waiting_logo_animation,
        LOGO_ATLAS_CELL_X * logo_factor, LOGO_ATLAS_CELL_Y * logo_factor);
    state->waiting_logo_frames_dirty = TRUE;
    refresh_waiting_logo();
}

/* update_waiting_logo rebuilds textures and restarts only when the status color changes. */
static void update_waiting_logo(const char* severity)
{
    RendererState* state = renderer_state();
    if (state->waiting_logo == NULL)
    {
        return;
    }

    GdkRGBA next_color;
    logo_status_color(severity, &next_color);
    if (gdk_rgba_equal(&state->waiting_logo_color, &next_color))
    {
        return;
    }
    state->waiting_logo_color = next_color;
    state->waiting_logo_frames_dirty = TRUE;
    state->waiting_logo_cycle_started = g_get_monotonic_time();
    state->waiting_logo_current_frame = 0;
    refresh_waiting_logo();
}

/* show_waiting_screen makes the native waiting screen visible. */
void show_waiting_screen(void)
{
    if (renderer_state()->waiting_view == NULL || renderer_state()->stack == NULL)
    {
        return;
    }

    gtk_stack_set_visible_child(GTK_STACK(renderer_state()->stack), renderer_state()->waiting_view);
}

/* update_waiting_screen updates native waiting-screen widgets with text only. */
void update_waiting_screen(void)
{
    RendererState* state = renderer_state();
    if (state->waiting_view == NULL)
    {
        return;
    }

    gtk_label_set_text(GTK_LABEL(state->waiting_status),
        state->default_status_message != NULL ? state->default_status_message
                                              : DEFAULT_STATUS_MESSAGE);
    update_waiting_logo(state->default_status_severity);
    if (state->show_device_info)
    {
        char* info = g_strdup_printf("%s    •    LAN: %s    •    VPN: %s",
            state->default_agent_name != NULL ? state->default_agent_name : "Unknown agent",
            state->default_agent_ip != NULL ? state->default_agent_ip : "IP unavailable",
            state->default_tunnel_ip != NULL ? state->default_tunnel_ip : "unavailable");
        gtk_label_set_text(GTK_LABEL(state->waiting_info), info);
        g_free(info);
    }
}

/* create_waiting_screen builds native widgets without owning the renderer stack. */
void create_waiting_screen(void)
{
    configure_waiting_screen();
    renderer_state()->waiting_view = gtk_overlay_new();
    gtk_widget_add_css_class(renderer_state()->waiting_view, "waiting-screen");
    /* Only this empty child sizes the screen, so the logo cannot widen the window. */
    GtkWidget* screen = gtk_drawing_area_new();
    g_signal_connect(screen, "resize", G_CALLBACK(fit_waiting_logo), NULL);
    gtk_overlay_set_child(GTK_OVERLAY(renderer_state()->waiting_view), screen);
    GtkWidget* waiting_logo_layer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(waiting_logo_layer, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(waiting_logo_layer, GTK_ALIGN_CENTER);
    gtk_overlay_add_overlay(GTK_OVERLAY(renderer_state()->waiting_view), waiting_logo_layer);
    const char* wordmark_path = NEODSE_ASSET_DIR "/logo-wordmark.png";
    renderer_state()->waiting_logo_wordmark = cairo_image_surface_create_from_png(wordmark_path);
    if (cairo_surface_status(renderer_state()->waiting_logo_wordmark) != CAIRO_STATUS_SUCCESS)
    {
        g_printerr("[UI] ! Cannot load waiting wordmark %s: %s\n", wordmark_path,
            cairo_status_to_string(cairo_surface_status(renderer_state()->waiting_logo_wordmark)));
        cairo_surface_destroy(renderer_state()->waiting_logo_wordmark);
        renderer_state()->waiting_logo_wordmark = NULL;
    }
    /* fit_waiting_logo sizes and places these widgets at the first allocation. */
    renderer_state()->waiting_logo = gtk_fixed_new();
    gtk_widget_add_css_class(renderer_state()->waiting_logo, "waiting-logo");
    renderer_state()->waiting_logo_wordmark_area = gtk_drawing_area_new();
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(renderer_state()->waiting_logo_wordmark_area),
        draw_waiting_wordmark, NULL, NULL);
    gtk_fixed_put(GTK_FIXED(renderer_state()->waiting_logo),
        renderer_state()->waiting_logo_wordmark_area, 0.0, 0.0);
    renderer_state()->waiting_logo_animation = gtk_picture_new();
    gtk_picture_set_can_shrink(GTK_PICTURE(renderer_state()->waiting_logo_animation), TRUE);
    g_signal_connect(renderer_state()->waiting_logo_animation, "map",
        G_CALLBACK(waiting_logo_mapping_changed), NULL);
    g_signal_connect(renderer_state()->waiting_logo_animation, "unmap",
        G_CALLBACK(waiting_logo_mapping_changed), NULL);
    g_signal_connect(renderer_state()->waiting_logo_animation, "notify::scale-factor",
        G_CALLBACK(waiting_logo_scale_changed), NULL);
    g_signal_connect_object(gtk_widget_get_settings(renderer_state()->waiting_logo_animation),
        "notify::gtk-enable-animations", G_CALLBACK(waiting_logo_settings_changed),
        renderer_state()->waiting_logo_animation, 0);
    gtk_fixed_put(
        GTK_FIXED(renderer_state()->waiting_logo), renderer_state()->waiting_logo_animation, 0, 0);
    gtk_widget_set_halign(renderer_state()->waiting_logo, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(renderer_state()->waiting_logo, GTK_ALIGN_CENTER);
    gtk_widget_set_hexpand(renderer_state()->waiting_logo, FALSE);
    gtk_widget_set_vexpand(renderer_state()->waiting_logo, FALSE);
    gtk_box_append(GTK_BOX(waiting_logo_layer), renderer_state()->waiting_logo);
    renderer_state()->waiting_status = gtk_label_new(DEFAULT_STATUS_MESSAGE);
    gtk_widget_add_css_class(renderer_state()->waiting_status, "waiting-status");
    gtk_label_set_wrap(GTK_LABEL(renderer_state()->waiting_status), TRUE);
    gtk_label_set_justify(GTK_LABEL(renderer_state()->waiting_status), GTK_JUSTIFY_CENTER);
    gtk_label_set_max_width_chars(GTK_LABEL(renderer_state()->waiting_status), 64);
    gtk_widget_set_size_request(renderer_state()->waiting_status, 640, -1);
    gtk_widget_set_halign(renderer_state()->waiting_status, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(renderer_state()->waiting_status, GTK_ALIGN_END);
    gtk_widget_set_margin_bottom(renderer_state()->waiting_status, 180);
    gtk_widget_set_visible(renderer_state()->waiting_status, renderer_state()->show_status_message);
    gtk_overlay_add_overlay(
        GTK_OVERLAY(renderer_state()->waiting_view), renderer_state()->waiting_status);
    renderer_state()->waiting_info = gtk_label_new("");
    gtk_widget_add_css_class(renderer_state()->waiting_info, "waiting-info");
    gtk_widget_set_halign(renderer_state()->waiting_info, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(renderer_state()->waiting_info, GTK_ALIGN_END);
    gtk_widget_set_margin_bottom(renderer_state()->waiting_info, 48);
    gtk_widget_set_margin_start(renderer_state()->waiting_info, 24);
    gtk_widget_set_margin_end(renderer_state()->waiting_info, 24);
    gtk_label_set_wrap(GTK_LABEL(renderer_state()->waiting_info), TRUE);
    gtk_label_set_justify(GTK_LABEL(renderer_state()->waiting_info), GTK_JUSTIFY_CENTER);
    gtk_widget_set_visible(renderer_state()->waiting_info, renderer_state()->show_device_info);
    gtk_overlay_add_overlay(
        GTK_OVERLAY(renderer_state()->waiting_view), renderer_state()->waiting_info);
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider,
        ".waiting-screen { background: #000; }"
        " .waiting-logo { opacity: 1; }"
        " .waiting-status { color: #777f8a; font-size: 20px; font-weight: 500; }"
        " .waiting-info { color: #777f8a; font-size: 16px; }");
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

/* destroy_waiting_screen releases animation timers, cached textures and masks. */
void destroy_waiting_screen(void)
{
    if (renderer_state()->waiting_logo_timer != 0)
    {
        g_source_remove(renderer_state()->waiting_logo_timer);
        renderer_state()->waiting_logo_timer = 0;
    }
    for (int frame = 0; frame < LOGO_FRAME_COUNT; frame++)
    {
        g_clear_object(&renderer_state()->waiting_logo_frames[frame]);
        g_clear_pointer(&renderer_state()->waiting_logo_masks[frame], cairo_surface_destroy);
    }
    g_clear_pointer(&renderer_state()->waiting_logo_wordmark, cairo_surface_destroy);
    g_clear_pointer(&renderer_state()->logo_atlas, cairo_surface_destroy);
}
