#pragma once

#include <stddef.h>
#include <stdbool.h>

struct buffered_fd;

enum shim_request_type {
    PAM_SHIM_REQUEST_NONE = 0,
    PAM_SHIM_REQUEST_START,
    PAM_SHIM_REQUEST_END,
    PAM_SHIM_REQUEST_AUTHENTICATE,
    PAM_SHIM_REQUEST_SET_CRED,
    PAM_SHIM_REQUEST_ACCT_MGMT,
    PAM_SHIM_REQUEST_OPEN_SESSION,
    PAM_SHIM_REQUEST_CLOSE_SESSION,
    PAM_SHIM_REQUEST_CHAUTHTOK,
    PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE,
    PAM_SHIM_REQUEST_SET_ITEM,
    PAM_SHIM_REQUEST_GET_ITEM,
    PAM_SHIM_REQUEST_STRERROR,
    PAM_SHIM_REQUEST_PUTENV,
    PAM_SHIM_REQUEST_GETENV,
    PAM_SHIM_REQUEST_GETENVLIST,
    PAM_SHIM_REQUEST_FAIL_DELAY,
};

struct shim_request {
    enum shim_request_type type;
    union {
        // PAM_SHIM_REQUEST_START
        struct {
            const char *service_name;
            const char *user;
            const char *confdir;
        } start;

        // PAM_SHIM_REQUEST_AUTHENTICATE_RESPONSE
        struct {
            struct pam_response *messages;
            size_t message_count;
        } authenticate_response;

        // PAM_SHIM_REQUEST_SET_ITEM
        struct {
            void *handle;
            int item_type;
            const void *item;
        } set_item;

        // PAM_SHIM_REQUEST_GET_ITEM
        struct {
            void *handle;
            int item_type;
        } get_item;

        // PAM_SHIM_REQUEST_PUTENV, PAM_SHIM_REQUEST_GETENV
        struct {
            void *handle;
            const char *name;
        } env;

        // All other requests (except NONE)
        struct {
            void *handle;
            int flags;
        } default_call;
    } data;
};

bool shim_request_read(struct buffered_fd *bfd, struct shim_request *request);
bool shim_request_write(struct buffered_fd *bfd, const struct shim_request *request);
void shim_request_destroy(struct shim_request *request);

enum shim_response_type {
    PAM_SHIM_RESPONSE_NONE = 0,
    PAM_SHIM_RESPONSE_HANDLE,
    PAM_SHIM_RESPONSE_RESULT,
    PAM_SHIM_RESPONSE_CONVERSATION,
    PAM_SHIM_RESPONSE_AUTHENTICATE,
    PAM_SHIM_RESPONSE_ITEM,
    PAM_SHIM_RESPONSE_STRING,
    PAM_SHIM_RESPONSE_STRING_LIST,
};

struct shim_response {
    enum shim_response_type type;
    union {
        // PAM_SHIM_RESPONSE_HANDLE
        struct {
            int pam_status;
            void *handle;
        } handle;

        // PAM_SHIM_RESPONSE_RESULT
        struct {
            int pam_status;
        } result;

        // PAM_SHIM_RESPONSE_CONVERSATION
        struct {
            const struct pam_message **messages;
            size_t message_count;
        } conversation;

        // PAM_SHIM_RESPONSE_AUTHENTICATE
        struct {
            int pam_status;
            int delay_retval;
            unsigned delay_usec;
        } authenticate;

        // PAM_SHIM_RESPONSE_ITEM
        struct {
            int pam_status;
            int item_type;
            const void *item;
        } item;

        // PAM_SHIM_RESPONSE_STRING
        const char *string;

        // PAM_SHIM_RESPONSE_STRING_LIST
        char **string_list;
    } data;
};

bool shim_response_read(struct buffered_fd *bfd, struct shim_response *response);
bool shim_response_write(struct buffered_fd *bfd, const struct shim_response *response);
void shim_response_destroy(struct shim_response *response);
