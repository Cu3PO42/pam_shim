#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "shim/shared/message.h"
#include "shim/shared/buffered_fd.h"

struct pipes {
    struct buffered_fd *in;
    struct buffered_fd *out;
};

int conv_fn(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata_ptr) {
    struct pipes *pipes = (struct pipes *)appdata_ptr;

    int result = PAM_CONV_ERR;

    struct shim_response response = {
        .type = PAM_SHIM_RESPONSE_CONVERSATION,
        .data.conversation = {
            .messages = msg,
            .message_count = (size_t)num_msg,
        },
    };
    struct shim_request request = {0};

    if (shim_response_write(pipes->out, &response) &&
        shim_request_read(pipes->in, &request) &&
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

int main(int argc, char** argv){
    int ipc_out = dup(1);
    if (ipc_out < 0 || dup2(2, 1) < 0) {
        fprintf(stderr, "Failed to setup IPC pipes\n");
        return 1;
    }

    struct pipes pipes = {
        .in = buffered_fd_new(0),
        .out = buffered_fd_new(ipc_out),
    };
    if (!pipes.in || !pipes.out) {
        fprintf(stderr, "Failed to create buffered fds\n");
        // Open fds and memory is cleaned up when the process exits
        return 1;
    }

    struct pam_conv conv = {
        .conv = &conv_fn,
        .appdata_ptr = &pipes,
    };

    struct shim_request request = {0};
    struct shim_response response = {0};

    for (bool running = false, did_end = false; !did_end;) {
        if (!shim_request_read(pipes.in, &request)) {
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
                running = (res == PAM_SUCCESS);
                break;
            }

            case PAM_SHIM_REQUEST_AUTHENTICATE:
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status =
                    pam_authenticate((pam_handle_t *)request.data.default_call.handle,
                                     request.data.default_call.flags);
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

            default:
                fprintf(stderr, "Unknown request type: %d\n", request.type);
                response.type = PAM_SHIM_RESPONSE_RESULT;
                response.data.result.pam_status = PAM_SYSTEM_ERR;
                break;
        }

        if (!shim_response_write(pipes.out, &response)) {
            fprintf(stderr, "Failed to write shim response\n");
            return 1;
        }

        shim_request_destroy(&request);
    }

    // Open fds and memory is cleaned up when the process exits
    return 0;
}
