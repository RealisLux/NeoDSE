/*
 * File purpose: Applies explicit navigation, permission, download, and TLS policy.
 * Copyright (c) 2026 RealisLux
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/RealisLux/NeoDSE
 */

#include "renderer_state.h"
#include "validation.h"

/* deny_permission prevents websites from acquiring host or user capabilities. */
static gboolean deny_permission(
    WebKitWebView* view, WebKitPermissionRequest* request, gpointer data)
{
    (void)view;
    (void)data;
    webkit_permission_request_deny(request);
    return TRUE;
}

/* dismiss_script_dialog keeps remote content from waiting for kiosk interaction. */
static gboolean dismiss_script_dialog(
    WebKitWebView* view, WebKitScriptDialog* dialog, gpointer data)
{
    (void)view;
    (void)data;
    WebKitScriptDialogType type = webkit_script_dialog_get_dialog_type(dialog);
    if (type == WEBKIT_SCRIPT_DIALOG_CONFIRM || type == WEBKIT_SCRIPT_DIALOG_BEFORE_UNLOAD_CONFIRM)
    {
        /* WebKit's before-unload implementation uses TRUE for Leave Page.
         * Some installed GIR documentation incorrectly describes TRUE as Stay. */
        webkit_script_dialog_confirm_set_confirmed(
            dialog, type == WEBKIT_SCRIPT_DIALOG_BEFORE_UNLOAD_CONFIRM);
    }
    /* Alert and prompt use their dismissed result. The synchronous dialog is
     * closed when WebKit releases it after this handled signal returns. */
    return TRUE;
}

/* deny_print prevents remote scripts from opening an unattended print dialog. */
static gboolean deny_print(WebKitWebView* view, WebKitPrintOperation* operation, gpointer data)
{
    (void)view;
    (void)operation;
    (void)data;
    return TRUE;
}

/* cancel_file_chooser prevents remote pages from opening a host-file upload surface. */
static gboolean cancel_file_chooser(
    WebKitWebView* view, WebKitFileChooserRequest* request, gpointer data)
{
    (void)view;
    (void)data;
    webkit_file_chooser_request_cancel(request);
    return TRUE;
}

/* cancel_download prevents persistent writes and unmanaged download surfaces. */
static void cancel_download(WebKitNetworkSession* session, WebKitDownload* download, gpointer data)
{
    (void)session;
    (void)data;
    webkit_download_cancel(download);
}

/* restrict_navigation allows only validated remote display URLs. */
static gboolean restrict_navigation(WebKitWebView* view, WebKitPolicyDecision* decision,
    WebKitPolicyDecisionType type, gpointer data)
{
    (void)view;
    (void)data;
    if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION)
    {
        webkit_policy_decision_ignore(decision);
        return TRUE;
    }
    if (type != WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION)
    {
        return FALSE;
    }
    WebKitNavigationAction* action = webkit_navigation_policy_decision_get_navigation_action(
        WEBKIT_NAVIGATION_POLICY_DECISION(decision));
    const char* uri = webkit_uri_request_get_uri(webkit_navigation_action_get_request(action));
    gboolean allowed
        = uri != NULL && (g_str_equal(uri, "about:blank") || neodse_valid_remote_url(uri));
    if (!allowed)
    {
        webkit_policy_decision_ignore(decision);
        return TRUE;
    }
    return FALSE;
}

/* browser_configure_view installs policy before the first navigation. */
void browser_configure_view(WebKitWebView* view)
{
    g_signal_connect(view, "permission-request", G_CALLBACK(deny_permission), NULL);
    g_signal_connect(view, "script-dialog", G_CALLBACK(dismiss_script_dialog), NULL);
    g_signal_connect(view, "run-file-chooser", G_CALLBACK(cancel_file_chooser), NULL);
    g_signal_connect(view, "print", G_CALLBACK(deny_print), NULL);
    g_signal_connect(view, "decide-policy", G_CALLBACK(restrict_navigation), NULL);
}

/* browser_configure_session keeps invalid certificates fatal and downloads disabled. */
void browser_configure_session(WebKitNetworkSession* session)
{
    webkit_network_session_set_tls_errors_policy(session, WEBKIT_TLS_ERRORS_POLICY_FAIL);
    g_signal_connect(session, "download-started", G_CALLBACK(cancel_download), NULL);
}
