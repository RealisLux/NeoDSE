/*
 * File purpose: Declares the authenticated local command interface exposed by
 * the renderer to the NeoDSE agent.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#ifndef NEODSE_IPC_H
#define NEODSE_IPC_H

#include <glib.h>
#include <sys/types.h>

#define NEODSE_IPC_MAX_BYTES (1024U * 1024U)

/* Cancels queued work and joins the IPC listener during shutdown. */
void ipc_stop(void);
void ipc_cancel_pending(void);

/* Reads one bounded JSON line through the peer's write half-close. */
ssize_t ipc_receive_message(int client, char* buffer, size_t capacity);

/* Starts the authenticated Unix-domain IPC listener. */
gboolean ipc_start(void);

/* Rechecks queued playlist work after the renderer proxy state changes. */
void ipc_proxy_state_changed(void);

/* Parses one bounded command and optionally waits for main-thread application. */
gboolean ipc_process_message(
    const char* message, char** error_message, gboolean wait_for_application);

#endif
