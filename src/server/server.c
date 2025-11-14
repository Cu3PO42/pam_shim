#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "shim/shared/message.h"
#include "shim/shared/buffered_fd.h"

struct appdata {
    struct buffered_fd *in;
    struct buffered_fd *out;

    int delay_retval;
    unsigned delay_usec;
};

int conv_fn(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata_ptr) {
    struct appdata *appdata = (struct appdata *)appdata_ptr;

    int result = PAM_CONV_ERR;

    struct shim_response response = {
        .type = PAM_SHIM_RESPONSE_CONVERSATION,
        .data.conversation = {
            .messages = msg,
            .message_count = (size_t)num_msg,
        },
    };
    struct shim_request request = {0};

    if (shim_response_write(appdata->out, &response) &&
        shim_request_read(appdata->in, &request) &&
        request.type == PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE &&
        num_msg == (int)request.data.authenticate_response.message_count) {
        *resp = request.data.authenticate_response.messages;
        // We steal the allocated responses, so prevent use-after-free
        request.type = PAM_SHIM_REQUEST_NONE;
        result = PAM_SUCCESS;
    }

    shim_request_destroy(&request);
    return result;
}

void delay_fn(int retval, unsigned usec_delay, void *appdata_ptr) {
    // Simply store these values. They will be sent out to the caller, who
    // will perform the actual delay.
    struct appdata *appdata = (struct appdata *)appdata_ptr;
    appdata->delay_retval = retval;
    appdata->delay_usec = usec_delay;
}

int main(int argc, char** argv){
    int ipc_out = dup(1);
    if (ipc_out < 0 || dup2(2, 1) < 0) {
        fprintf(stderr, "Failed to setup IPC pipes\n");
        return 1;
    }

    struct appdata appdata = {
        .in = buffered_fd_new(0),
        .out = buffered_fd_new(ipc_out),

        .delay_retval = 0,
        .delay_usec = 0,
    };
    if (!appdata.in || !appdata.out) {
        fprintf(stderr, "Failed to create buffered fds\n");
        // Open fds and memory is cleaned up when the process exits
        return 1;
    }

    struct pam_conv conv = {
        .conv = &conv_fn,
        .appdata_ptr = &appdata,
    };

    struct shim_request request = {0};
    struct shim_response response = {0};

    for (bool running = false, did_end = false; !did_end;) {
        if (!shim_request_read(appdata.in, &request)) {
            fprintf(stderr, "Failed to read shim request\n");
            return 2;
        }

        switch (request.type) {
            case PAM_SHIM_REQUEST_START: {
                response.type = PAM_SHIM_RESPONSE_HANDLE;
                if (running) {
                    response.data.handle.pam_status = PAM_SYSTEM_ERR;
                    break;
                }

                pam_handle_t *handle = NULL;
                int res;
                if (request.data.start.confdir == NULL)
                    res = pam_start(request.data.start.service_name,
                            request.data.start.user,
                           &conv,
                           &handle);
                else
                    res = pam_start_confdir(request.data.start.service_name,
                                      request.data.start.user,
                                      &conv,
                                      request.data.start.confdir,
                                      &handle);
                response.data.handle.pam_status = res;
                response.data.handle.handle = (void *)handle;
                if (res == PAM_SUCCESS) {
                    // We always initialize custom delay handling to reduce possible states.
                    response.data.handle.pam_status = res = pam_set_item(handle, PAM_FAIL_DELAY, (void *)delay_fn);
                }
                running = (res == PAM_SUCCESS);
                break;
            }

            case PAM_SHIM_REQUEST_AUTHENTICATE:
                response.type = PAM_SHIM_RESPONSE_AUTHENTICATE;
                response.data.authenticate.pam_status =
                    pam_authenticate((pam_handle_t *)request.data.default_call.handle,
                                     request.data.default_call.flags);
                response.data.authenticate.delay_retval = appdata.delay_retval;
                response.data.authenticate.delay_usec = appdata.delay_usec;
                // Reset delay values for next call.
                appdata.delay_retval = 0;
                appdata.delay_usec = 0;
                break;

            case PAM_SHIM_REQUEST_END:
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status =
                    pam_end((pam_handle_t *)request.data.default_call.handle,
                            request.data.default_call.flags);
                running = false;
                did_end = true;
                break;

            #define HANDLE_DEFAULT_PAM_CALL(req_type, pam_func) \
            case req_type: \
                response.type = PAM_SHIM_RESPONSE_RESULT; \
                response.data.result.pam_status = \
                    pam_func((pam_handle_t *)request.data.default_call.handle, \
                             request.data.default_call.flags); \
                break;
            HANDLE_DEFAULT_PAM_CALL(PAM_SHIM_REQUEST_SET_CRED, pam_setcred)
            HANDLE_DEFAULT_PAM_CALL(PAM_SHIM_REQUEST_ACCT_MGMT, pam_acct_mgmt)
            HANDLE_DEFAULT_PAM_CALL(PAM_SHIM_REQUEST_OPEN_SESSION, pam_open_session)
            HANDLE_DEFAULT_PAM_CALL(PAM_SHIM_REQUEST_CLOSE_SESSION, pam_close_session)
            HANDLE_DEFAULT_PAM_CALL(PAM_SHIM_REQUEST_CHAUTHTOK, pam_chauthtok)
            #undef HANDLE_DEFAULT_PAM_CALL

            case PAM_SHIM_REQUEST_SET_ITEM:
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status =
                    pam_set_item((pam_handle_t *)request.data.set_item.handle,
                                 request.data.set_item.item_type,
                                 request.data.set_item.item);
                break;

            case PAM_SHIM_REQUEST_GET_ITEM: {
                response.type = PAM_SHIM_RESPONSE_ITEM;
                const void *item = NULL;
                // Memory returned by pam_get_item is owned by the PAM session,
                // we do not need to free it.
                response.data.item.pam_status =
                    pam_get_item((pam_handle_t *)request.data.get_item.handle,
                                 request.data.get_item.item_type,
                                 &item);
                response.data.item.item_type = request.data.get_item.item_type;
                response.data.item.item = item;
                break;
            }

            case PAM_SHIM_REQUEST_STRERROR: {
                response.type = PAM_SHIM_RESPONSE_STRING;
                response.data.string =
                    pam_strerror(
                        (pam_handle_t *)request.data.default_call.handle,
                        request.data.default_call.flags);
                break;
            }

            case PAM_SHIM_REQUEST_PUTENV:
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status =
                    pam_putenv((pam_handle_t *)request.data.env.handle,
                               request.data.env.name);
                break;

            case PAM_SHIM_REQUEST_GETENV:
                response.type = PAM_SHIM_RESPONSE_STRING;
                response.data.string =
                    pam_getenv(
                        (pam_handle_t *)request.data.env.handle,
                        request.data.env.name);
                break;

            case PAM_SHIM_REQUEST_GETENVLIST: {
                response.type = PAM_SHIM_RESPONSE_STRING_LIST;
                response.data.string_list =
                    pam_getenvlist(
                        (pam_handle_t *)request.data.default_call.handle);
                break;
            }

            case PAM_SHIM_REQUEST_FAIL_DELAY:
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status =
                    pam_fail_delay((pam_handle_t *)request.data.default_call.handle,
                                   (unsigned)request.data.default_call.flags);
                break;

            default:
                fprintf(stderr, "Unknown request type: %d\n", request.type);
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status = PAM_SYSTEM_ERR;
                break;
        }

        if (!shim_response_write(appdata.out, &response)) {
            fprintf(stderr, "Failed to write shim response\n");
            return 1;
        }

        if (response.type == PAM_SHIM_RESPONSE_STRING_LIST) {
            // The data returned by pam_getenvlist is owned and must be freed by us.
            for (char **env = response.data.string_list; env && *env; env++) {
                free(*env);
            }
            free(response.data.string_list);
        }

        shim_request_destroy(&request);
    }

    // Open fds and memory is cleaned up when the process exits
    return 0;
}
