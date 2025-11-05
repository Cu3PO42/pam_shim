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
    } data;
};

bool shim_response_read(struct buffered_fd *bfd, struct shim_response *response);
bool shim_response_write(struct buffered_fd *bfd, const struct shim_response *response);
void shim_response_destroy(struct shim_response *response);
