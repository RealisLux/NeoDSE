/*
 * File purpose: Validates renderer CLI arguments and starts the IPC service,
 * GTK/WebKit UI, and GLib application loop.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include <glib-unix.h>
#include <gtk/gtk.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "ipc.h"
#include "webview.h"

#ifndef NEODSE_VERSION
#define NEODSE_VERSION "dev"
#endif

/* stop_main_loop requests orderly shutdown from a Unix signal. */
static gboolean stop_main_loop(gpointer data)
{
    g_main_loop_quit(data);
    return G_SOURCE_CONTINUE;
}

/* main handles version output and runs the renderer until its window closes. */
int main(int argc, char** argv)
{
    GMainLoop* main_loop;

    (void)setvbuf(stdout, NULL, _IOLBF, 0);
    (void)setvbuf(stderr, NULL, _IOLBF, 0);

    if (argc == 2 && strcmp(argv[1], "--version") == 0)
    {
        printf("neodse-ui %s\n", NEODSE_VERSION);
        return 0;
    }
    if (argc != 1)
    {
        fprintf(stderr, "usage: neodse-ui [--version]\n");
        return 2;
    }

    gtk_init();
    webview_init();
    if (!ipc_start())
    {
        fprintf(stderr, "neodse-ui: IPC initialization failed\n");
        webview_destroy();
        return 1;
    }
    main_loop = g_main_loop_new(NULL, FALSE);
    webview_set_main_loop(main_loop);
    guint term_source = g_unix_signal_add(SIGTERM, stop_main_loop, main_loop);
    guint int_source = g_unix_signal_add(SIGINT, stop_main_loop, main_loop);
    g_main_loop_run(main_loop);
    g_source_remove(term_source);
    g_source_remove(int_source);
    ipc_stop();
    webview_destroy();
    g_main_loop_unref(main_loop);

    return 0;
}
