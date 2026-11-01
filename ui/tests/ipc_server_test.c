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
#include <fcntl.h>
#include <glib.h>
#include <pwd.h>
#include <stdio.h>
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
static char* fixture_directory;
static gboolean wrong_directory_owner;
static gboolean fail_directory_stat;
static gboolean fail_socket_lookup;
static gboolean fail_socket_chmod;
static int fixture_directory_fd = -1;

int __real_accept4(int socket, struct sockaddr* address, socklen_t* length, int flags);
int __real_bind(int socket, const struct sockaddr* address, socklen_t length);
int __real_open(const char* path, int flags, ...);
int __real_openat(int directory, const char* path, int flags, ...);
int __real_fstat(int fd, struct stat* information);
int __real_fchmodat(int directory, const char* path, mode_t mode, int flags);
struct passwd* __real_getpwnam(const char* name);
int __open_2(const char* path, int flags);
int __openat_2(int directory, const char* path, int flags);

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

/* __wrap_open redirects the production directory while preserving its open flags. */
int __wrap_open(const char* path, int flags, ...)
{
    g_assert_cmpint(flags & O_CREAT, ==, 0);
    if (fixture_directory != NULL && strcmp(path, "/run/neodse") == 0)
    {
        g_assert_true((flags & (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
            == (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        fixture_directory_fd = __real_open(fixture_directory, flags);
        return fixture_directory_fd;
    }
    return __real_open(path, flags);
}

/* __wrap_openat preserves descriptor-relative lookups and injects a lookup failure. */
int __wrap_openat(int directory, const char* path, int flags, ...)
{
    g_assert_cmpint(flags & O_CREAT, ==, 0);
    if (directory == fixture_directory_fd && fail_socket_lookup)
    {
        errno = EACCES;
        return -1;
    }
    return __real_openat(directory, path, flags);
}

/* Clang's glibc fortification uses these symbols for opens without a mode. */
int __wrap___open_2(const char* path, int flags) { return __wrap_open(path, flags); }

int __wrap___openat_2(int directory, const char* path, int flags)
{
    return __wrap_openat(directory, path, flags);
}

/* __wrap_fstat models an unsafe owner or an unavailable directory metadata lookup. */
int __wrap_fstat(int fd, struct stat* information)
{
    if (fd == fixture_directory_fd && fail_directory_stat)
    {
        errno = EIO;
        return -1;
    }
    int result = __real_fstat(fd, information);
    if (result == 0 && fd == fixture_directory_fd && wrong_directory_owner)
    {
        information->st_uid = geteuid() + 1;
    }
    return result;
}

/* __wrap_fchmodat injects a failure after bind to exercise socket cleanup. */
int __wrap_fchmodat(int directory, const char* path, mode_t mode, int flags)
{
    if (directory == fixture_directory_fd && fail_socket_chmod)
    {
        errno = EACCES;
        return -1;
    }
    return __real_fchmodat(directory, path, mode, flags);
}

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

/* prepare_fixture isolates the runtime directory and socket without starting the server. */
static void prepare_fixture(void)
{
    GError* error = NULL;
    fixture_directory = g_dir_make_tmp("neodse-ipc-server-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(fixture_directory);
    fixture_socket_path = g_strdup_printf("/run/neodse/test-ipc-%d.sock", (int)getpid());
    fixture_actual_path
        = g_build_filename(fixture_directory, strrchr(fixture_socket_path, '/') + 1, NULL);
    g_setenv("NEODSE_UI_SOCKET", fixture_socket_path, TRUE);
    g_atomic_int_set(&receive_started, FALSE);
}

/* start_fixture starts the listener on an isolated socket and returns its real path. */
static const char* start_fixture(void)
{
    prepare_fixture();
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
    fixture_directory_fd = -1;
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

static void test_stale_socket(void)
{
    prepare_fixture();
    int stale = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    g_assert_cmpint(stale, >=, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    g_strlcpy(address.sun_path, fixture_actual_path, sizeof(address.sun_path));
    g_assert_cmpint(bind(stale, (struct sockaddr*)&address, sizeof(address)), ==, 0);
    close(stale);
    g_assert_true(ipc_start());
    ipc_stop();
    finish_fixture();
}

/* Exercise fortified entry points even on hosts whose headers still call open/openat. */
static void test_fortified_opens(void)
{
    prepare_fixture();
    int directory = __open_2("/run/neodse", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    g_assert_cmpint(directory, >=, 0);
    g_assert_true(g_file_set_contents(fixture_actual_path, "preserve", -1, NULL));
    const char* name = strrchr(fixture_socket_path, '/') + 1;
    int entry = __openat_2(directory, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    g_assert_cmpint(entry, >=, 0);
    close(entry);
    fail_socket_lookup = TRUE;
    g_assert_cmpint(__openat_2(directory, name, O_PATH | O_NOFOLLOW | O_CLOEXEC), ==, -1);
    g_assert_cmpint(errno, ==, EACCES);
    fail_socket_lookup = FALSE;
    close(directory);
    g_assert_cmpint(unlink(fixture_actual_path), ==, 0);
    finish_fixture();
}

static void test_refuse_existing_entry(gconstpointer kind)
{
    prepare_fixture();
    char* target = g_build_filename(fixture_directory, "target", NULL);
    g_assert_true(g_file_set_contents(target, "preserve", -1, NULL));
    if (strcmp(kind, "symlink") == 0)
    {
        g_assert_cmpint(symlink(target, fixture_actual_path), ==, 0);
    }
    else if (strcmp(kind, "directory") == 0)
    {
        g_assert_cmpint(mkdir(fixture_actual_path, 0700), ==, 0);
    }
    else
    {
        g_assert_true(g_file_set_contents(fixture_actual_path, "preserve", -1, NULL));
    }
    struct stat entry;
    g_assert_cmpint(lstat(fixture_actual_path, &entry), ==, 0);
    mode_t original_mode = entry.st_mode;
    g_assert_false(ipc_start());
    g_assert_cmpint(lstat(fixture_actual_path, &entry), ==, 0);
    if (strcmp(kind, "symlink") == 0)
    {
        g_assert_true(S_ISLNK(entry.st_mode));
    }
    else if (strcmp(kind, "directory") == 0)
    {
        g_assert_true(S_ISDIR(entry.st_mode));
    }
    else
    {
        g_assert_true(S_ISREG(entry.st_mode));
    }
    char* contents = NULL;
    g_assert_true(g_file_get_contents(target, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "preserve");
    g_free(contents);
    g_assert_cmpuint(entry.st_mode, ==, original_mode);
    if (S_ISDIR(entry.st_mode))
    {
        g_assert_cmpint(rmdir(fixture_actual_path), ==, 0);
    }
    else
    {
        g_assert_cmpint(unlink(fixture_actual_path), ==, 0);
    }
    g_assert_cmpint(unlink(target), ==, 0);
    g_free(target);
    finish_fixture();
}

static void test_unsafe_directory(gconstpointer kind)
{
    prepare_fixture();
    g_assert_true(g_file_set_contents(fixture_actual_path, "preserve", -1, NULL));
    wrong_directory_owner = strcmp(kind, "owner") == 0;
    fail_directory_stat = strcmp(kind, "stat") == 0;
    mode_t mode = strcmp(kind, "group") == 0 ? 0770 : strcmp(kind, "world") == 0 ? 0702 : 0700;
    g_assert_cmpint(chmod(fixture_directory, mode), ==, 0);
    g_assert_false(ipc_start());
    wrong_directory_owner = FALSE;
    fail_directory_stat = FALSE;
    g_assert_cmpint(chmod(fixture_directory, 0700), ==, 0);
    char* contents = NULL;
    g_assert_true(g_file_get_contents(fixture_actual_path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "preserve");
    g_free(contents);
    g_assert_cmpint(unlink(fixture_actual_path), ==, 0);
    finish_fixture();
}

static void test_symlink_directory(void)
{
    prepare_fixture();
    char* actual_directory = g_strconcat(fixture_directory, "-actual", NULL);
    g_assert_cmpint(rename(fixture_directory, actual_directory), ==, 0);
    g_assert_cmpint(symlink(actual_directory, fixture_directory), ==, 0);
    g_assert_false(ipc_start());
    g_assert_cmpint(unlink(fixture_directory), ==, 0);
    g_assert_cmpint(rename(actual_directory, fixture_directory), ==, 0);
    g_free(actual_directory);
    finish_fixture();
}

static void test_socket_failures(gconstpointer kind)
{
    prepare_fixture();
    fail_socket_lookup = strcmp(kind, "lookup") == 0;
    fail_socket_chmod = strcmp(kind, "chmod") == 0;
    g_assert_false(ipc_start());
    fail_socket_lookup = FALSE;
    fail_socket_chmod = FALSE;
    /* Failure must release resources and allow a fresh start. */
    g_assert_cmpint(access(fixture_actual_path, F_OK), !=, 0);
    g_assert_true(ipc_start());
    ipc_stop();
    finish_fixture();
}

static void test_stop_captured_path(void)
{
    start_fixture();
    char* replacement = g_build_filename(fixture_directory, "replacement.sock", NULL);
    g_assert_true(g_file_set_contents(replacement, "preserve", -1, NULL));
    g_setenv("NEODSE_UI_SOCKET", "/run/neodse/replacement.sock", TRUE);
    ipc_stop();
    g_assert_true(g_file_test(replacement, G_FILE_TEST_IS_REGULAR));
    g_assert_cmpint(unlink(replacement), ==, 0);
    g_free(replacement);
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
    g_test_add_func("/ipc-server/stale-socket", test_stale_socket);
    g_test_add_func("/ipc-server/fortified-opens", test_fortified_opens);
    g_test_add_data_func("/ipc-server/refuse-file", "file", test_refuse_existing_entry);
    g_test_add_data_func("/ipc-server/refuse-symlink", "symlink", test_refuse_existing_entry);
    g_test_add_data_func("/ipc-server/refuse-directory", "directory", test_refuse_existing_entry);
    g_test_add_data_func("/ipc-server/unsafe-group-writable", "group", test_unsafe_directory);
    g_test_add_data_func("/ipc-server/unsafe-world-writable", "world", test_unsafe_directory);
    g_test_add_data_func("/ipc-server/unsafe-owner", "owner", test_unsafe_directory);
    g_test_add_data_func("/ipc-server/directory-stat-failure", "stat", test_unsafe_directory);
    g_test_add_func("/ipc-server/symlink-directory", test_symlink_directory);
    g_test_add_data_func("/ipc-server/lookup-failure", "lookup", test_socket_failures);
    g_test_add_data_func("/ipc-server/chmod-failure", "chmod", test_socket_failures);
    g_test_add_func("/ipc-server/stop-captured-path", test_stop_captured_path);
    return g_test_run();
}
