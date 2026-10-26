/*
 * File purpose: Exercises the authenticated IPC listener lifecycle, shutdown
 * interruption, and recovery from failing accepts.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#define _GNU_SOURCE

#include "../ipc.h"

#include <errno.h>
#include <glib.h>
#include <pwd.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static gint receive_started;
static gint accept_calls;
static char* fixture_socket_path;
static char* fixture_actual_path;

int __real_accept4(int socket, struct sockaddr* address, socklen_t* length, int flags);
int __real_bind(int socket, const struct sockaddr* address, socklen_t length);
int __real_lstat(const char* path, struct stat* information);
int __real_chmod(const char* path, mode_t mode);
int __real_unlink(const char* path);
struct passwd* __real_getpwnam(const char* name);

/* fixture_path redirects only this test's socket into its private temporary directory. */
static const char* fixture_path(const char* path)
{
    return fixture_socket_path != NULL && strcmp(path, fixture_socket_path) == 0
        ? fixture_actual_path
        : path;
}

/* __wrap_accept4 counts listener wakeups while delegating to the real call. */
int __wrap_accept4(int socket, struct sockaddr* address, socklen_t* length, int flags)
{
    g_atomic_int_inc(&accept_calls);
    return __real_accept4(socket, address, length, flags);
}

/* __wrap_bind preserves production socket validation while isolating filesystem writes. */
int __wrap_bind(int socket, const struct sockaddr* address, socklen_t length)
{
    if (address->sa_family == AF_UNIX && length == sizeof(struct sockaddr_un))
    {
        const struct sockaddr_un* original = (const struct sockaddr_un*)address;
        const char* path = fixture_path(original->sun_path);
        if (path != original->sun_path)
        {
            struct sockaddr_un redirected = *original;
            g_assert_cmpuint(strlen(path), <, sizeof(redirected.sun_path));
            g_strlcpy(redirected.sun_path, path, sizeof(redirected.sun_path));
            return __real_bind(socket, (const struct sockaddr*)&redirected, sizeof(redirected));
        }
    }
    return __real_bind(socket, address, length);
}

/* File-operation wrappers follow the same isolated socket as bind. */
int __wrap_lstat(const char* path, struct stat* information)
{
    return __real_lstat(fixture_path(path), information);
}

int __wrap_chmod(const char* path, mode_t mode) { return __real_chmod(fixture_path(path), mode); }

int __wrap_unlink(const char* path) { return __real_unlink(fixture_path(path)); }

/* __wrap_getpwnam makes the current unprivileged test process the configured agent. */
struct passwd* __wrap_getpwnam(const char* name)
{
    if (strcmp(name, "neodse-agent") == 0)
    {
        static struct passwd account;
        account.pw_uid = geteuid();
        return &account;
    }
    return __real_getpwnam(name);
}

/* ipc_receive_message blocks until the test client or server closes. */
ssize_t ipc_receive_message(int client, char* buffer, size_t capacity)
{
    g_atomic_int_set(&receive_started, TRUE);
    ssize_t received = recv(client, buffer, capacity, 0);
    return received < 0 ? -1 : received;
}

/* The lifecycle test does not enqueue renderer work. */
void ipc_cancel_pending(void) { }

/* ipc_process_message is unreachable because the client sends no command. */
gboolean ipc_process_message(
    const char* message, char** error_message, gboolean wait_for_application)
{
    (void)message;
    (void)error_message;
    (void)wait_for_application;
    return FALSE;
}

static char* fixture_directory;

/* start_fixture starts the listener on an isolated socket and returns its real path. */
static const char* start_fixture(void)
{
    GError* error = NULL;
    fixture_directory = g_dir_make_tmp("neodse-ipc-server-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(fixture_directory);
    fixture_socket_path = g_strdup_printf("/run/neodse/test-ipc-%d.sock", (int)getpid());
    fixture_actual_path = g_build_filename(fixture_directory, "ui.sock", NULL);
    g_setenv("NEODSE_UI_SOCKET", fixture_socket_path, TRUE);
    g_atomic_int_set(&receive_started, FALSE);
    g_assert_true(ipc_start());
    return fixture_actual_path;
}

/* finish_fixture requires that stopping the listener removed its socket. */
static void finish_fixture(void)
{
    g_assert_cmpint(access(fixture_actual_path, F_OK), !=, 0);
    g_unsetenv("NEODSE_UI_SOCKET");
    g_free(fixture_socket_path);
    g_free(fixture_actual_path);
    fixture_socket_path = NULL;
    fixture_actual_path = NULL;
    g_assert_cmpint(rmdir(fixture_directory), ==, 0);
    g_clear_pointer(&fixture_directory, g_free);
}

/* connect_client returns a client whose request the listener has started reading. */
static int connect_client(const char* path, gint64 timeout)
{
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    g_assert_cmpint(client, >=, 0);

    struct sockaddr_un address = { 0 };
    address.sun_family = AF_UNIX;
    g_strlcpy(address.sun_path, path, sizeof(address.sun_path));
    g_assert_cmpint(connect(client, (struct sockaddr*)&address, sizeof(address)), ==, 0);

    gint64 deadline = g_get_monotonic_time() + timeout;
    while (!g_atomic_int_get(&receive_started) && g_get_monotonic_time() < deadline)
    {
        g_usleep(1000);
    }
    g_assert_true(g_atomic_int_get(&receive_started));
    return client;
}

static void test_server_start_stop(void)
{
    const char* path = start_fixture();
    struct stat socket_stat = { 0 };
    g_assert_cmpint(stat(path, &socket_stat), ==, 0);
    g_assert_true(S_ISSOCK(socket_stat.st_mode));
    g_assert_cmpint(socket_stat.st_mode & 0777, ==, 0660);
    int client = connect_client(path, G_TIME_SPAN_SECOND);
    ipc_stop();
    close(client);
    finish_fixture();
}

/* Exhausted descriptors fail accept immediately; the listener must pause, not spin. */
static void test_accept_failure_pauses(void)
{
    const char* path = start_fixture();
    int served = connect_client(path, G_TIME_SPAN_SECOND);

    struct rlimit limit;
    g_assert_cmpint(getrlimit(RLIMIT_NOFILE, &limit), ==, 0);
    struct rlimit exhausted = { .rlim_cur = 3, .rlim_max = limit.rlim_max };
    g_assert_cmpint(setrlimit(RLIMIT_NOFILE, &exhausted), ==, 0);
    gint before = g_atomic_int_get(&accept_calls);
    g_atomic_int_set(&receive_started, FALSE);
    /* The listener answers, closes this client and returns to accept. */
    g_assert_cmpint(shutdown(served, SHUT_WR), ==, 0);
    g_usleep(300 * 1000);
    gint failed_accepts = g_atomic_int_get(&accept_calls) - before;
    g_assert_cmpint(setrlimit(RLIMIT_NOFILE, &limit), ==, 0);
    g_assert_cmpint(failed_accepts, <=, 2);

    int recovered = connect_client(path, 3 * G_TIME_SPAN_SECOND);
    ipc_stop();
    close(recovered);
    close(served);
    finish_fixture();
}

int main(int argc, char** argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ipc-server/start-stop-blocked-client", test_server_start_stop);
    g_test_add_func("/ipc-server/accept-failure-pauses", test_accept_failure_pauses);
    return g_test_run();
}
