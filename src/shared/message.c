#include "shim/shared/message.h"

#include <security/pam_appl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "shim/shared/buffered_fd.h"
#include "shim/shared/util.h"

#define TRY(expr) if (!(expr)) return false;
#define HANDLE(path) TRY((read ? buffered_fd_read_exact : buffered_fd_write_exact)(bfd, &(path), sizeof(path)))
#define HANDLE_STR(path) TRY((read ? read_str : write_str)(bfd, (path)))
#define HANDLE_ARR(path, count_path, elem) do { \
    HANDLE(count_path); \
    if (read) { \
        if ((count_path) > 0) { \
            void *tmp = calloc((count_path), sizeof(*(path))); \
            if (!tmp) return false; \
            (path) = tmp; \
        } else { \
            (path) = NULL; \
        } \
    } \
    for (size_t i = 0; i < (count_path); i++) { \
        TRY((read ? read_##elem : write_##elem)(bfd, &(path)[i])); \
    } \
} while (0)

static bool read_str(struct buffered_fd *bfd, char **str) {
    size_t len;
    TRY(buffered_fd_read_exact(bfd, &len, sizeof(len)));
    if (len == 0) {
        *str = NULL;
        return true;
    }
    *str = malloc(len);
    if (!*str) return false;
    TRY(buffered_fd_read_exact(bfd, *str, len));
    return true;
}

static bool write_str(struct buffered_fd *bfd, char **strp) {
    char *str = *strp;
    size_t len = str ? strlen(str) + 1 : 0;
    TRY(buffered_fd_write_exact(bfd, &len, sizeof(len)));
    if (len > 0) {
        TRY(buffered_fd_write_exact(bfd, str, len));
    }
    return true;
}

static bool handle_string_list(struct buffered_fd *bfd, char ***str_list_ptr, bool read) {
    if (read) {
        size_t count;
        TRY(buffered_fd_read_exact(bfd, &count, sizeof(count)));
        char **arr = malloc((count + 1) * sizeof(char *));
        if (!arr) return false;
        for (size_t i = 0; i < count; ++i) {
            TRY(read_str(bfd, &arr[i]));
        }
        arr[count] = NULL;
        *str_list_ptr = arr;
    } else {
        size_t count = 0;
        for (char **str_list = *str_list_ptr; *str_list; ++str_list, ++count);
        TRY(buffered_fd_write_exact(bfd, &count, sizeof(count)));
        for (char **str_list = *str_list_ptr; *str_list; ++str_list) {
            TRY(write_str(bfd, str_list));
        }
    }
    return true;
}

static bool handle_pam_xauth_data(struct buffered_fd *bfd, struct pam_xauth_data **xauth, bool read) {
    if (read) {
        *xauth = malloc(sizeof(struct pam_xauth_data));
        if (!*xauth) return false;
    }
    HANDLE((*xauth)->namelen);
    HANDLE_STR(&(*xauth)->name);
    HANDLE((*xauth)->datalen);
    HANDLE_STR(&(*xauth)->data);
    return true;
}

static bool handle_item(struct buffered_fd *bfd, int item_type, const void **item_ptr, bool read) {
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
            HANDLE_STR((char **)item_ptr);
            break;
        case PAM_XAUTHDATA:
            TRY(handle_pam_xauth_data(bfd, (struct pam_xauth_data **)item_ptr, read));
            break;
        default:
            // Unsupported item type
            return false;
    }
    return true;
}

static bool handle_pam_message(struct buffered_fd *bfd, struct pam_message *msg, bool read) {
    HANDLE(msg->msg_style);
    HANDLE_STR((char **)&msg->msg);
    return true;
}

static bool read_pam_message(struct buffered_fd *bfd, struct pam_message *msg) {
    return handle_pam_message(bfd, msg, true);
}

static bool write_pam_message(struct buffered_fd *bfd, const struct pam_message *msg) {
    return handle_pam_message(bfd, (struct pam_message *)msg, false);
}

static bool read_pam_message_ptr(struct buffered_fd *bfd, const struct pam_message **msg_ptr) {
    struct pam_message *msg = malloc(sizeof(*msg));
    if (!msg) return false;
    if (!read_pam_message(bfd, msg)) {
        free(msg);
        return false;
    }
    *msg_ptr = msg;
    return true;
}

static bool write_pam_message_ptr(struct buffered_fd *bfd, const struct pam_message **msg_ptr) {
    return write_pam_message(bfd, *msg_ptr);
}

static bool handle_shim_response(struct buffered_fd *bfd, struct shim_response *response, bool read) {
    HANDLE(response->type);
    switch (response->type) {
        case PAM_SHIM_RESPONSE_HANDLE:
            HANDLE(response->data.handle);
            break;
        case PAM_SHIM_RESPONSE_RESULT:
            HANDLE(response->data.result);
            break;
        case PAM_SHIM_RESPONSE_CONVERSATION: {
            HANDLE_ARR(response->data.conversation.messages, response->data.conversation.message_count, pam_message_ptr);
            break;
        }
        case PAM_SHIM_RESPONSE_AUTHENTICATE:
            HANDLE(response->data.authenticate);
            break;
        case PAM_SHIM_RESPONSE_ITEM:
            HANDLE(response->data.item.pam_status);
            HANDLE(response->data.item.item_type);
            TRY(handle_item(bfd, response->data.item.item_type, (const void **)&response->data.item.item, read));
            break;
        case PAM_SHIM_RESPONSE_STRING:
            HANDLE_STR((char **)&response->data.string);
            break;
        case PAM_SHIM_RESPONSE_STRING_LIST: 
            TRY(handle_string_list(bfd, &response->data.string_list, read));
            break;

        case PAM_SHIM_RESPONSE_NONE:
        default:
            return false;
    }
    return true;
}

bool shim_response_write(struct buffered_fd *bfd, const struct shim_response *response) {
    bool res = handle_shim_response(bfd, (struct shim_response *)response, false);
    if (res) {
        res = buffered_fd_flush(bfd);
    }
    return res;
}

bool shim_response_read(struct buffered_fd *bfd, struct shim_response *response) {
    bool res = handle_shim_response(bfd, response, true);
    if (!res) response->type = PAM_SHIM_RESPONSE_NONE;
    return res;
}

void shim_response_destroy(struct shim_response *response) {
    if (!response) return;
    switch (response->type) {
        case PAM_SHIM_RESPONSE_CONVERSATION: {
            const struct pam_message **messages = response->data.conversation.messages;
            size_t count = response->data.conversation.message_count;
            if (messages) {
                for (size_t i = 0; i < count; i++) {
                    const struct pam_message *msg = messages[i];
                    if (msg) {
                        if (msg->msg) free((char *)msg->msg);
                        free((void *)msg);
                    }
                }
                free(messages);
            }
            break;
        }
        case PAM_SHIM_RESPONSE_ITEM:
            free_item(response->data.item.item_type, (void *)response->data.item.item);
            break;
        case PAM_SHIM_RESPONSE_STRING:
            if (response->data.string) free((char *)response->data.string);
            break;
        case PAM_SHIM_RESPONSE_STRING_LIST: {
            for (char **str = response->data.string_list; str && *str; str++) {
                free(*str);
            }
            free(response->data.string_list);
            break;
        }

        case PAM_SHIM_RESPONSE_HANDLE:
        case PAM_SHIM_RESPONSE_RESULT:
        case PAM_SHIM_RESPONSE_NONE:
        default:
            break;
    }
    response->type = PAM_SHIM_RESPONSE_NONE;
}

static bool handle_pam_response(struct buffered_fd *bfd, struct pam_response *resp, bool read) {
    HANDLE_STR(&resp->resp);
    HANDLE(resp->resp_retcode);
    return true;
}

static bool read_pam_response(struct buffered_fd *bfd, struct pam_response *resp) {
    return handle_pam_response(bfd, resp, true);
}

static bool write_pam_response(struct buffered_fd *bfd, struct pam_response *resp) {
    return handle_pam_response(bfd, (struct pam_response *)resp, false);
}

static bool handle_shim_request(struct buffered_fd *bfd, struct shim_request *request, bool read) {
    HANDLE(request->type);
    switch (request->type) {
        case PAM_SHIM_REQUEST_START:
            HANDLE(request->data.start);
            HANDLE_STR((char**)&request->data.start.service_name);
            HANDLE_STR((char**)&request->data.start.user);
            HANDLE_STR((char**)&request->data.start.confdir);
            break;
        case PAM_SHIM_REQUEST_AUTHENTICATE:
            HANDLE(request->data.default_call);
            break;
        case PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE:
            HANDLE_ARR(request->data.authenticate_response.messages, request->data.authenticate_response.message_count, pam_response);
            break;
        case PAM_SHIM_REQUEST_END:
        case PAM_SHIM_REQUEST_SET_CRED:
        case PAM_SHIM_REQUEST_ACCT_MGMT:
        case PAM_SHIM_REQUEST_OPEN_SESSION:
        case PAM_SHIM_REQUEST_CLOSE_SESSION:
        case PAM_SHIM_REQUEST_CHAUTHTOK:
        case PAM_SHIM_REQUEST_STRERROR:
        case PAM_SHIM_REQUEST_GETENVLIST:
        case PAM_SHIM_REQUEST_FAIL_DELAY:
            HANDLE(request->data.default_call);
            break;
        case PAM_SHIM_REQUEST_SET_ITEM:
            HANDLE(request->data.set_item.handle);
            HANDLE(request->data.set_item.item_type);
            TRY(handle_item(bfd, request->data.set_item.item_type, &request->data.set_item.item, read));
            break;
        case PAM_SHIM_REQUEST_GET_ITEM:
            HANDLE(request->data.get_item);
        case PAM_SHIM_REQUEST_PUTENV:
        case PAM_SHIM_REQUEST_GETENV:
            HANDLE(request->data.env);
            HANDLE_STR((char**)&request->data.env.name);
            break;
        case PAM_SHIM_REQUEST_NONE:
        default:
            return false;
    }
    return true;
}

bool shim_request_write(struct buffered_fd *bfd, const struct shim_request *request) {
    bool res = handle_shim_request(bfd, (struct shim_request *)request, false);
    if (res) {
        res = buffered_fd_flush(bfd);
    }
    return res;
}

bool shim_request_read(struct buffered_fd *bfd, struct shim_request *request) {
    bool res = handle_shim_request(bfd, request, true);
    if (!res) request->type = PAM_SHIM_REQUEST_NONE;
    return res;
}

void shim_request_destroy(struct shim_request *request) {
    if (!request) return;
    switch (request->type) {
        case PAM_SHIM_REQUEST_START:
            if (request->data.start.service_name) free((char *)request->data.start.service_name);
            if (request->data.start.user) free((char *)request->data.start.user);
            if (request->data.start.confdir) free((char *)request->data.start.confdir);
            break;

        case PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE: {
            struct pam_response *responses = request->data.authenticate_response.messages;
            size_t count = request->data.authenticate_response.message_count;
            free_responses(responses, count);
            break;
        }

        case PAM_SHIM_REQUEST_SET_ITEM:
            free_item(request->data.set_item.item_type, (void *)request->data.set_item.item);
            break;
        
        case PAM_SHIM_REQUEST_PUTENV:
        case PAM_SHIM_REQUEST_GETENV:
            if (request->data.env.name) free((char *)request->data.env.name);
            break;

        case PAM_SHIM_REQUEST_END:
        case PAM_SHIM_REQUEST_SET_CRED:
        case PAM_SHIM_REQUEST_ACCT_MGMT:
        case PAM_SHIM_REQUEST_OPEN_SESSION:
        case PAM_SHIM_REQUEST_CLOSE_SESSION:
        case PAM_SHIM_REQUEST_CHAUTHTOK:
        case PAM_SHIM_REQUEST_AUTHENTICATE:
        case PAM_SHIM_REQUEST_NONE:
        default:
            break;
    }
    request->type = PAM_SHIM_REQUEST_NONE;
}