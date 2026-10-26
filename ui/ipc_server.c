/*
 * File purpose: Owns the peer-authenticated Unix socket listener and bounded
 * request-response transport for the renderer IPC boundary.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#define _GNU_SOURCE

#include "ipc.h"
#include "validation.h"

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static struct
{
    pthread_t thread;
    pthread_mutex_t mutex;
    int listener;
    int client;
    gint stopping;
    gboolean started;
} ipc_server = { .mutex = PTHREAD_MUTEX_INITIALIZER, .listener = -1, .client = -1 };

#define DEFAULT_SOCKET_PATH "/run/neodse/ui.sock"
/* Descriptor exhaustion fails every accept at once until a descriptor is freed. */
#define ACCEPT_RETRY_DELAY_US G_USEC_PER_SEC

/* socket_path returns the configured renderer socket or its safe runtime default. */
static const char* socket_path(void)
{
    const char* configured = g_getenv("NEODSE_UI_SOCKET");
    return configured != NULL && configured[0] != '\0' ? configured : DEFAULT_SOCKET_PATH;
}

/* send_response writes one bounded semantic JSON result to the connected agent. */
static void send_response(int client, gboolean accepted, const char* error_message)
{
    char* allocated_response = NULL;
    const char* response = NULL;

    if (accepted)
    {
        response = "{\"status\":\"accepted\"}\n";
    }
    else
    {
        char* escaped_error
            = g_strescape(error_message != NULL ? error_message : "invalid command", NULL);
        allocated_response = g_strdup_printf("{\"status\":\"rejected\",\"error\":\"%s\"}\n",
            escaped_error != NULL ? escaped_error : "invalid command");
        g_free(escaped_error);
        response = allocated_response;
    }
    if (response == NULL)
    {
        return;
    }
    size_t total = 0;
    size_t length = strlen(response);

    while (total < length)
    {
        ssize_t written = send(client, response + total, length - total, MSG_NOSIGNAL);
        if (written <= 0)
        {
            g_free(allocated_response);
            return;
        }
        total += (size_t)written;
    }

    g_free(allocated_response);
}

/* ---------- socket loop ---------- */

/* open_ipc_socket safely replaces the expected socket and begins listening. */
static int open_ipc_socket(void)
{
    const char* path = socket_path();
    struct sockaddr_un addr = { 0 };
    addr.sun_family = AF_UNIX;
    if (!neodse_valid_socket_path(path, sizeof(addr.sun_path)))
    {
        g_printerr("[IPC] ! Socket path must be a bounded path under /run/neodse\n");
        return -1;
    }
    struct stat existing;
    if (lstat(path, &existing) == 0)
    {
        if (!S_ISSOCK(existing.st_mode) || unlink(path) < 0)
        {
            g_printerr("[IPC] ! Refusing to replace socket path: %s\n", path);
            return -1;
        }
    }
    else if (errno != ENOENT)
    {
        g_printerr("[IPC] ! Socket path lookup failed: %s\n", g_strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        g_printerr("[IPC] ! Socket creation failed: %s\n", g_strerror(errno));
        return -1;
    }

    memcpy(addr.sun_path, path, strlen(path) + 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        g_printerr("[IPC] ! Socket bind failed: %s\n", g_strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 5) < 0)
    {
        g_printerr("[IPC] ! Socket listen failed: %s\n", g_strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    if (chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
    {
        g_printerr("[IPC] ! Socket permission change failed: %s\n", g_strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }

    g_print("[IPC] Listening on %s\n", path);
    return fd;
}

/* ipc_thread authenticates peers and serves one bounded request per connection. */
static void* ipc_thread(void* arg)
{
    int fd = GPOINTER_TO_INT(arg);

    while (!g_atomic_int_get(&ipc_server.stopping))
    {
        struct sockaddr_un peer_address = { 0 };
        socklen_t peer_address_length = sizeof(peer_address);
        int client
            = accept4(fd, (struct sockaddr*)&peer_address, &peer_address_length, SOCK_CLOEXEC);
        if (client < 0)
        {
            if (g_atomic_int_get(&ipc_server.stopping))
            {
                break;
            }
            if (errno != EINTR)
            {
                g_printerr("[IPC] ! Accept failed: %s\n", g_strerror(errno));
                g_usleep(ACCEPT_RETRY_DELAY_US);
            }
            continue;
        }
        struct timeval timeout = { .tv_sec = 10, .tv_usec = 0 };
        (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

#ifdef SO_PEERCRED
        struct ucred cred;
        socklen_t credlen = sizeof(cred);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) == 0)
        {
            struct passwd* agent_account = getpwnam("neodse-agent");
            if (cred.uid != 0
                && (agent_account == NULL
                    || !neodse_valid_peer_uid(cred.uid, agent_account->pw_uid)))
            {
                g_printerr(
                    "[IPC] ! Connection rejected: uid=%u not allowed\n", (unsigned int)cred.uid);
                close(client);
                continue;
            }
        }
        else
        {
            g_printerr("[IPC] ! Peer credential lookup failed: %s\n", g_strerror(errno));
            close(client);
            continue;
        }
#else
        g_printerr("[IPC] ! Peer credentials are unsupported on this platform\n");
        close(client);
        continue;
#endif

        pthread_mutex_lock(&ipc_server.mutex);
        ipc_server.client = client;
        if (g_atomic_int_get(&ipc_server.stopping))
        {
            (void)shutdown(client, SHUT_RDWR);
        }
        pthread_mutex_unlock(&ipc_server.mutex);
        char* buffer = g_try_malloc(NEODSE_IPC_MAX_BYTES + 2U);
        ssize_t n
            = buffer != NULL ? ipc_receive_message(client, buffer, NEODSE_IPC_MAX_BYTES + 2U) : -1;

        if (n > 0)
        {
            char* error_message = NULL;
            gboolean accepted = ipc_process_message(buffer, &error_message, TRUE);
            send_response(client, accepted, error_message);
            g_free(error_message);
        }
        else
        {
            send_response(client, FALSE, n < 0 ? "invalid or oversized command" : "empty command");
        }

        g_free(buffer);
        pthread_mutex_lock(&ipc_server.mutex);
        close(client);
        ipc_server.client = -1;
        pthread_mutex_unlock(&ipc_server.mutex);
    }

    close(fd);
    return NULL;
}

/* ipc_start creates the listener and its owned server thread. */
gboolean ipc_start(void)
{
    int fd = open_ipc_socket();
    if (fd < 0)
    {
        return FALSE;
    }

    ipc_server.listener = fd;
    g_atomic_int_set(&ipc_server.stopping, FALSE);
    int result = pthread_create(&ipc_server.thread, NULL, ipc_thread, GINT_TO_POINTER(fd));
    if (result != 0)
    {
        close(fd);
        ipc_server.listener = -1;
        unlink(socket_path());
        return FALSE;
    }
    ipc_server.started = TRUE;
    return TRUE;
}

/* ipc_stop interrupts sockets, cancels application waits, and joins the thread. */
void ipc_stop(void)
{
    if (!ipc_server.started)
    {
        return;
    }
    ipc_cancel_pending();
    g_atomic_int_set(&ipc_server.stopping, TRUE);
    pthread_mutex_lock(&ipc_server.mutex);
    (void)shutdown(ipc_server.listener, SHUT_RDWR);
    if (ipc_server.client >= 0)
    {
        (void)shutdown(ipc_server.client, SHUT_RDWR);
    }
    pthread_mutex_unlock(&ipc_server.mutex);
    (void)pthread_join(ipc_server.thread, NULL);
    ipc_server.started = FALSE;
    ipc_server.listener = -1;
    (void)unlink(socket_path());
    while (g_main_context_pending(NULL))
    {
        (void)g_main_context_iteration(NULL, FALSE);
    }
}
