/*
 * File purpose: Reads exactly one bounded, terminated request from a local peer.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "ipc.h"
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>

/* ipc_receive_message reads one newline-terminated command without exceeding capacity. */
ssize_t ipc_receive_message(int client, char* buffer, size_t capacity)
{
    size_t total = 0;
    const gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
    while (total + 1 < capacity)
    {
        gint64 remaining = deadline - g_get_monotonic_time();
        if (remaining <= 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd descriptor = { .fd = client, .events = POLLIN };
        int ready = poll(&descriptor, 1, (int)((remaining + 999) / 1000));
        if (ready < 0 && errno != EINTR)
        {
            return -1;
        }
        if (ready <= 0)
        {
            continue;
        }
        if (descriptor.revents & POLLNVAL)
        {
            errno = EBADF;
            return -1;
        }
        ssize_t received = recv(client, buffer + total, capacity - total - 1, MSG_DONTWAIT);
        if (received < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            return -1;
        }
        if (received == 0)
        {
            break;
        }
        if (memchr(buffer + total, '\0', (size_t)received) != NULL)
        {
            errno = EINVAL;
            return -1;
        }
        total += (size_t)received;
    }
    if (total + 1 == capacity || total == 0 || total > NEODSE_IPC_MAX_BYTES
        || buffer[total - 1] != '\n' || memchr(buffer, '\n', total - 1) != NULL)
    {
        errno = EMSGSIZE;
        return -1;
    }
    buffer[total] = '\0';
    return (ssize_t)total;
}
