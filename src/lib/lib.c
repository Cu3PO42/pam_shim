#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
// We actually want to implement the functions here, so we define extern as empty
#define extern
#include <security/pam_appl.h>

#include "shim/shared/message.h"
#include "shim/shared/buffered_fd.h"
#include "shim/shared/util.h"
#include "shim/lib/remote.h"

int PAM_SHIM_REQUEST_MAGIC = 0x50414d53;

// The header only forward declares pam_handle, we can fill in whatever we want.
struct pam_handle {
    void *pam_server_handle;
    struct pam_conv *conv;
    struct remote remote;
    struct freelist *allocated_items;
    void (*delay_fn)(int retval, unsigned usec_delay, void *appdata_ptr);
};

int pam_start_confdir(const char *service_name, const char *user,
                      const struct pam_conv *pam_conversation,
                      const char *confdir, pam_handle_t **pamh) {
    int result = PAM_SYSTEM_ERR;

    pam_handle_t *handle = malloc(sizeof(*handle));
    if (!handle) {
        return PAM_BUF_ERR;
    }

    handle->pam_server_handle = NULL; // Placeholder for actual server handle, will be filled later
    handle->allocated_items = NULL;
    handle->conv = (struct pam_conv *)pam_conversation;
    handle->delay_fn = NULL;
    if (!remote_init(&handle->remote)) {
        free(handle);
        return PAM_SYSTEM_ERR;
    }

    struct shim_request start_request = {
        .type = PAM_SHIM_REQUEST_START,
        .data.start = {
            .service_name = service_name,
            .user = user,
            .confdir = confdir,
        },
    };
    struct shim_response start_response = {0};

    if (!remote_send(&handle->remote, &start_request)) goto cleanup;

    if (!remote_receive(&handle->remote, &start_response) || start_response.type != PAM_SHIM_RESPONSE_HANDLE)
        goto cleanup;

    if (start_response.data.handle.pam_status != PAM_SUCCESS) {
        result = start_response.data.handle.pam_status;
        goto cleanup;
    }

    handle->pam_server_handle = start_response.data.handle.handle;
    *pamh = handle;
    return PAM_SUCCESS;

cleanup:
    shim_response_destroy(&start_response);
    remote_close(&handle->remote);
    free(handle);
    return result;
}

int pam_start(const char *service_name, const char *user,
              const struct pam_conv *pam_conversation,
              pam_handle_t **pamh) {
    return pam_start_confdir(service_name, user, pam_conversation, NULL, pamh);
}

int pam_end(pam_handle_t *pamh, int pam_status) {
    int result = PAM_SYSTEM_ERR;

    struct shim_request end_request = {
        .type = PAM_SHIM_REQUEST_END,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = pam_status,
        },
    };
    struct shim_response end_response = {0};

    if (!remote_send(&pamh->remote, &end_request)) goto cleanup;   

    if (!remote_receive(&pamh->remote, &end_response) || end_response.type != PAM_SHIM_RESPONSE_RESULT) goto cleanup;

    result = end_response.data.result.pam_status;

cleanup:
    shim_response_destroy(&end_response);
    remote_close(&pamh->remote);
    freelist_free(pamh->allocated_items);
    free(pamh);
    return result;
}

#define TRY(expr) if (!(expr)) return PAM_SYSTEM_ERR;
int pam_authenticate(pam_handle_t *pamh, int flags) {
    int result = PAM_SYSTEM_ERR;

    struct shim_request auth_request = {
        .type = PAM_SHIM_REQUEST_AUTHENTICATE,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = flags,
        },
    };
    struct shim_response auth_response = {0};

    TRY(remote_send(&pamh->remote, &auth_request));

    for (;;) {
        TRY(remote_receive(&pamh->remote, &auth_response));
        if (auth_response.type == PAM_SHIM_RESPONSE_CONVERSATION) {
            const struct pam_message **messages = auth_response.data.conversation.messages;
            size_t message_count = auth_response.data.conversation.message_count;

            struct pam_response *responses = NULL;
            int conv_result = pamh->conv->conv((int)message_count,
                                               messages,
                                               &responses,
                                               pamh->conv->appdata_ptr);

            if (conv_result != PAM_SUCCESS) {
                result = conv_result;
                free_responses(responses, message_count);
                break;
            }

            if (message_count > 0 && !responses) {
                result = PAM_BUF_ERR;
                break;
            }

            struct shim_request auth_response_request = {
                .type = PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE,
                .data.authenticate_response = {
                    .messages = responses,
                    .message_count = message_count,
                },
            };

            bool sent = remote_send(&pamh->remote, &auth_response_request);
            free_responses(responses, message_count);
            if (sent) {
                shim_response_destroy(&auth_response);
                continue;
            }
        } else if (auth_response.type == PAM_SHIM_RESPONSE_AUTHENTICATE) {
            result = auth_response.data.authenticate.pam_status;
            if (pamh->delay_fn) {
                pamh->delay_fn(auth_response.data.authenticate.delay_retval,
                               auth_response.data.authenticate.delay_usec,
                               pamh->conv->appdata_ptr);
            } else if (result != PAM_SUCCESS && auth_response.data.authenticate.delay_usec > 0) {
                usleep(auth_response.data.authenticate.delay_usec);
            }
        }
        // Other (unexpected) response types are implicitly handled as errors
        break;
    }

    shim_response_destroy(&auth_response);
    return result;
}

static int pam_default_impl(pam_handle_t *pamh, int flags, enum shim_request_type req_type) {
    struct shim_request default_request = {
        .type = req_type,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = flags,
        },
    };
    TRY(remote_send(&pamh->remote, &default_request));

    struct shim_response default_response = {0};
    TRY(remote_receive(&pamh->remote, &default_response));
    if (default_response.type != PAM_SHIM_RESPONSE_RESULT) {
        shim_response_destroy(&default_response);
        return PAM_SYSTEM_ERR;
    }

    return default_response.data.result.pam_status;
}

#define IMPL(fun, req_type) \
int fun(pam_handle_t *pamh, int flags) { \
    return pam_default_impl(pamh, flags, req_type); \
}
IMPL(pam_setcred, PAM_SHIM_REQUEST_SET_CRED)
IMPL(pam_acct_mgmt, PAM_SHIM_REQUEST_ACCT_MGMT)
IMPL(pam_open_session, PAM_SHIM_REQUEST_OPEN_SESSION)
IMPL(pam_close_session, PAM_SHIM_REQUEST_CLOSE_SESSION)
IMPL(pam_chauthtok, PAM_SHIM_REQUEST_CHAUTHTOK)
#undef IMPL

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item) {
    switch (item_type) {
        case PAM_SERVICE:
        case PAM_USER:
        case PAM_USER_PROMPT:
        case PAM_TTY:
        case PAM_RUSER:
        case PAM_RHOST:
        case PAM_AUTHTOK:
        case PAM_OLDAUTHTOK:
        case PAM_XDISPLAY:
        case PAM_AUTHTOK_TYPE:
            // All of these are strings.
            break;

        case PAM_CONV:
            pamh->conv = (struct pam_conv *)item;
            return PAM_SUCCESS;

        case PAM_FAIL_DELAY:
            pamh->delay_fn = (void (*)(int, unsigned, void *))item;
            return PAM_SUCCESS;

        case PAM_XAUTHDATA:
            // This is a more complicated struct, which we do retrieve from the server.
            break;
        
        default:
            return PAM_BAD_ITEM;
    }

    struct shim_request set_item_request = {
        .type = PAM_SHIM_REQUEST_SET_ITEM,
        .data.set_item = {
            .handle = pamh->pam_server_handle,
            .item_type = item_type,
            .item = item,
        },
    };
    TRY(remote_send(&pamh->remote, &set_item_request));

    struct shim_response set_item_response;
    TRY(remote_receive(&pamh->remote, &set_item_response));
    if (set_item_response.type != PAM_SHIM_RESPONSE_RESULT) {
        shim_response_destroy(&set_item_response);
        return PAM_SYSTEM_ERR;
    }

    return set_item_response.data.result.pam_status;
}

int pam_get_item(const pam_handle_t *pamhc, int item_type, const void **item) {
    // We need to cast away const-ness here, as we need to track a freelist.
    pam_handle_t *pamh = (pam_handle_t *)pamhc;
    switch (item_type) {
        case PAM_SERVICE:
        case PAM_USER:
        case PAM_USER_PROMPT:
        case PAM_TTY:
        case PAM_RUSER:
        case PAM_RHOST:
        case PAM_AUTHTOK:
        case PAM_OLDAUTHTOK:
        case PAM_XDISPLAY:
        case PAM_AUTHTOK_TYPE:
            // All of these are strings.
            break;

        case PAM_CONV:
            *item = pamh->conv;
            return PAM_SUCCESS;

        case PAM_FAIL_DELAY:
            *item = (const void *)pamh->delay_fn;
            return PAM_SUCCESS;

        case PAM_XAUTHDATA:
            // This is a more complicated struct, which we do retrieve from the server.
            break;
        
        default:
            return PAM_BAD_ITEM;
    }

    struct shim_request get_item_request = {
        .type = PAM_SHIM_REQUEST_GET_ITEM,
        .data.get_item = {
            .handle = pamh->pam_server_handle,
            .item_type = item_type,
        },
    };
    TRY(remote_send(&pamh->remote, &get_item_request));

    struct shim_response get_item_response;
    TRY(remote_receive(&pamh->remote, &get_item_response));
    if (get_item_response.type != PAM_SHIM_RESPONSE_ITEM) {
        shim_response_destroy(&get_item_response);
        return PAM_SYSTEM_ERR;
    }

    int status = get_item_response.data.item.pam_status;
    if (status == PAM_SUCCESS) {
        *item = get_item_response.data.item.item;
        // We do not free get_item_response here, as the memory is returned and needs
        // to remain valid. We will free it in pam_end.
        pamh->allocated_items = freelist_append(pamh->allocated_items, (void *)get_item_response.data.item.item);
        if (item_type == PAM_XAUTHDATA) {
            // This is a more complicated struct, we need to track its internals as well.
            pamh->allocated_items = freelist_append(pamh->allocated_items, ((struct pam_xauth_data *)*item)->name);
            pamh->allocated_items = freelist_append(pamh->allocated_items, ((struct pam_xauth_data *)*item)->data);
        }
        return PAM_SUCCESS;
    }

    shim_response_destroy(&get_item_response);
    return status;
}

const char *pam_strerror(pam_handle_t *pamh, int errnum) {
    struct shim_request strerror_request = {
        .type = PAM_SHIM_REQUEST_STRERROR,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = errnum,
        },
    };
    if (!remote_send(&pamh->remote, &strerror_request)) return NULL;

    struct shim_response strerror_response;
    if (!remote_receive(&pamh->remote, &strerror_response)) return NULL;
    if (strerror_response.type != PAM_SHIM_RESPONSE_STRING) {
        shim_response_destroy(&strerror_response);
        return NULL;
    }

    // The application is not allowed to free the returned string, so we store
    // it to free later when pam_end is called.
    pamh->allocated_items = freelist_append(pamh->allocated_items, (void *)strerror_response.data.string);
    return strerror_response.data.string;
}

int pam_putenv(pam_handle_t *pamh, const char *name_value) {
    struct shim_request putenv_request = {
        .type = PAM_SHIM_REQUEST_PUTENV,
        .data.env = {
            .handle = pamh->pam_server_handle,
            .name = name_value,
        },
    };
    TRY(remote_send(&pamh->remote, &putenv_request));

    struct shim_response putenv_response;
    TRY(remote_receive(&pamh->remote, &putenv_response));
    if (putenv_response.type != PAM_SHIM_RESPONSE_RESULT) {
        shim_response_destroy(&putenv_response);
        return PAM_SYSTEM_ERR;
    }

    return putenv_response.data.result.pam_status;
}

const char *pam_getenv(pam_handle_t *pamh, const char *name) {
    struct shim_request getenv_request = {
        .type = PAM_SHIM_REQUEST_GETENV,
        .data.env = {
            .handle = pamh->pam_server_handle,
            .name = name,
        },
    };
    if (!remote_send(&pamh->remote, &getenv_request)) return NULL;

    struct shim_response getenv_response;
    if (!remote_receive(&pamh->remote, &getenv_response)) return NULL;
    if (getenv_response.type != PAM_SHIM_RESPONSE_STRING) {
        shim_response_destroy(&getenv_response);
        return NULL;
    }

    // The application is not allowed to free the returned string, so we store
    // it to free later when pam_end is called.
    pamh->allocated_items = freelist_append(pamh->allocated_items, (void *)getenv_response.data.string);
    return getenv_response.data.string;
}

char **pam_getenvlist(pam_handle_t *pamh) {
    struct shim_request getenvlist_request = {
        .type = PAM_SHIM_REQUEST_GETENVLIST,
        .data.default_call = {
            .handle = pamh->pam_server_handle,
            .flags = 0,
        },
    };
    if (!remote_send(&pamh->remote, &getenvlist_request)) return NULL;

    struct shim_response getenvlist_response;
    if (!remote_receive(&pamh->remote, &getenvlist_response)) return NULL;
    if (getenvlist_response.type != PAM_SHIM_RESPONSE_STRING_LIST) {
        shim_response_destroy(&getenvlist_response);
        return NULL;
    }

    // Intentionally do not free the strings, we are handing the memory
    // ownership to the caller.
    return getenvlist_response.data.string_list;
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int musec_delay) {
    // int and unsigned int are guaranteed to be the same size
    return pam_default_impl(pamh, (int)musec_delay, PAM_SHIM_REQUEST_FAIL_DELAY);
}
