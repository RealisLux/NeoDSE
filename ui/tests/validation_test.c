/*
 * File purpose: Verifies URL, socket, proxy credential, scheduling, and peer
 * identity validation at renderer trust boundaries.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "../validation.h"

#include <glib.h>

/* test_scales rejects NaN, infinity, invalid text, and out-of-range GTK dimensions. */
static void test_scales(void)
{
    const char* invalid[] = { NULL, "", "nan", "NaN", "nan(1)", "inf", "-inf", "1e999", "0.49",
        "3.01", "1px", "1.0 " };
    for (size_t i = 0; i < G_N_ELEMENTS(invalid); i++)
    {
        double scale = 1.0;
        g_assert_false(neodse_parse_scale(invalid[i], 0.5, 3.0, &scale));
        g_assert_cmpfloat(scale, ==, 1.0);
    }
    double scale;
    g_assert_true(neodse_parse_scale("0.5", 0.5, 3.0, &scale));
    g_assert_cmpfloat(scale, ==, 0.5);
    g_assert_true(neodse_parse_scale("3.0", 0.5, 3.0, &scale));
    g_assert_cmpfloat(scale, ==, 3.0);
}

/* test_environment_settings keeps defaults for unset and invalid display.env values. */
static void test_environment_settings(void)
{
    const char* name = "NEODSE_TEST_SETTING";

    g_unsetenv(name);
    g_assert_cmpfloat(neodse_env_scale(name, 1.0), ==, 1.0);
    g_assert_true(neodse_env_visibility(name, TRUE));
    g_assert_false(neodse_env_visibility(name, FALSE));
    g_setenv(name, "", TRUE);
    g_assert_cmpfloat(neodse_env_scale(name, 1.0), ==, 1.0);
    g_assert_false(neodse_env_visibility(name, FALSE));
    g_setenv(name, "2.5", TRUE);
    g_assert_cmpfloat(neodse_env_scale(name, 1.0), ==, 2.5);
    g_setenv(name, "3.5", TRUE);
    g_assert_cmpfloat(neodse_env_scale(name, 1.0), ==, 1.0);
    g_setenv(name, "show", TRUE);
    g_assert_true(neodse_env_visibility(name, FALSE));
    g_setenv(name, "hide", TRUE);
    g_assert_false(neodse_env_visibility(name, TRUE));
    g_setenv(name, "Show", TRUE);
    g_assert_true(neodse_env_visibility(name, TRUE));
    g_assert_false(neodse_env_visibility(name, FALSE));
    g_unsetenv(name);
}

/* test_remote_urls distinguishes safe remote content from local or credentialed URLs. */
static void test_remote_urls(void)
{
    g_assert_true(neodse_valid_remote_url("https://display.example/screen"));
    g_assert_true(neodse_valid_remote_url("http://192.0.2.10:8080/path"));
    g_assert_false(neodse_valid_remote_url("https://[2001:db8::1]/screen"));
    g_assert_false(neodse_valid_remote_url("file:///etc/passwd"));
    g_assert_false(neodse_valid_remote_url("https://user@example.test/"));
    g_assert_false(neodse_valid_remote_url("//example.test/path"));
    g_assert_false(neodse_valid_remote_url(NULL));
}

/* test_socket_paths confines IPC endpoints to the bounded runtime directory. */
static void test_socket_paths(void)
{
    g_assert_true(neodse_valid_socket_path("/run/neodse/ui.sock", 108));
    g_assert_false(neodse_valid_socket_path("/run/neodse/", 108));
    g_assert_false(neodse_valid_socket_path("/run/neodse/../ui.sock", 108));
    g_assert_false(neodse_valid_socket_path("/run/neodse/nested/ui.sock", 108));
    g_assert_false(neodse_valid_socket_path("/tmp/ui.sock", 108));
}

/* test_proxy_credentials verifies loopback routing and credential alphabets. */
static void test_proxy_credentials(void)
{
    g_assert_true(neodse_valid_proxy_url("http://127.0.0.1:3129"));
    g_assert_false(neodse_valid_proxy_url("http://[::1]:3129/"));
    g_assert_false(neodse_valid_proxy_url("http://192.0.2.10:3129"));
    g_assert_false(neodse_valid_proxy_url("https://127.0.0.1:3129"));
    g_assert_false(neodse_valid_proxy_url("http://127.0.0.1"));
    g_assert_false(neodse_valid_proxy_url("http://127.0.0.1:65536"));
    g_assert_true(neodse_valid_agent_id("display_01-a"));
    g_assert_false(neodse_valid_agent_id("../display"));
    g_assert_true(neodse_valid_agent_id("0123456789abcdef0123456789abcdef"));
    g_assert_false(neodse_valid_agent_id("0123456789abcdef0123456789abcdef0"));
    g_assert_true(neodse_valid_proxy_token(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    g_assert_false(neodse_valid_proxy_token(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"));
}

/* test_playlist_timing checks both edges of supported scheduling bounds. */
static void test_playlist_timing(void)
{
    g_assert_true(neodse_valid_playlist_timing(0, 0));
    g_assert_true(neodse_valid_playlist_timing(86400, 4102444800));
    g_assert_false(neodse_valid_playlist_timing(-1, 0));
    g_assert_false(neodse_valid_playlist_timing(86401, 0));
    g_assert_false(neodse_valid_playlist_timing(1, 4102444801));
    g_assert_false(neodse_valid_playlist_timing(PLAYLIST_INTERVAL_MIN - 1, 0));
    g_assert_true(neodse_valid_playlist_timing(PLAYLIST_INTERVAL_MIN, 0));
}

/* test_playlist_interval permits no interval for one page and requires one for several. */
static void test_playlist_interval(void)
{
    g_assert_true(neodse_valid_playlist_interval(0, 1));
    g_assert_false(neodse_valid_playlist_interval(PLAYLIST_INTERVAL_MIN, 1));
    g_assert_false(neodse_valid_playlist_interval(0, 2));
    g_assert_false(neodse_valid_playlist_interval(PLAYLIST_INTERVAL_MIN - 1, 2));
    g_assert_true(neodse_valid_playlist_interval(PLAYLIST_INTERVAL_MIN, 2));
    g_assert_true(neodse_valid_playlist_interval(PLAYLIST_INTERVAL_MAX, 6));
    g_assert_false(neodse_valid_playlist_interval(PLAYLIST_INTERVAL_MAX + 1, 2));
}

/* test_peer_credentials authorizes root and the configured agent UID only. */
static void test_peer_credentials(void)
{
    g_assert_true(neodse_valid_peer_uid(0, 1001));
    g_assert_true(neodse_valid_peer_uid(1001, 1001));
    g_assert_false(neodse_valid_peer_uid(1002, 1001));
}

/* test_proxy_failure_status separates proxy outages from ordinary site errors. */
static void test_proxy_failure_status(void)
{
    for (guint status = 502; status <= 504; status++)
    {
        g_assert_true(neodse_proxy_failure_status(status));
    }
    g_assert_true(neodse_proxy_failure_status(407));
    g_assert_false(neodse_proxy_failure_status(404));
    g_assert_false(neodse_proxy_failure_status(500));
    g_assert_false(neodse_proxy_failure_status(505));
}

/* test_transport_failure_stage rejects initial connection and healthy stages. */
static void test_transport_failure_stage(void)
{
    g_assert_true(neodse_transport_failure_stage("connection_lost"));
    g_assert_false(neodse_transport_failure_stage("connecting_control"));
    g_assert_false(neodse_transport_failure_stage("waiting_for_playlist"));
    g_assert_false(neodse_transport_failure_stage(NULL));
}

/* main registers and executes the renderer validation suite. */
int main(int argc, char** argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/validation/scales", test_scales);
    g_test_add_func("/validation/environment-settings", test_environment_settings);
    g_test_add_func("/validation/remote-urls", test_remote_urls);
    g_test_add_func("/validation/socket-paths", test_socket_paths);
    g_test_add_func("/validation/proxy-credentials", test_proxy_credentials);
    g_test_add_func("/validation/playlist-timing", test_playlist_timing);
    g_test_add_func("/validation/playlist-interval", test_playlist_interval);
    g_test_add_func("/validation/peer-credentials", test_peer_credentials);
    g_test_add_func("/validation/proxy-failure-status", test_proxy_failure_status);
    g_test_add_func("/validation/transport-failure-stage", test_transport_failure_stage);
    return g_test_run();
}
