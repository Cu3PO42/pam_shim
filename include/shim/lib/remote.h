#pragma once

#include <stdbool.h>

struct buffered_fd;
struct shim_request;
struct shim_response;

struct remote {
    int server_pid;
    struct buffered_fd *stdin;
    struct buffered_fd *stdout;
};

bool remote_init(struct remote *remote);
bool remote_close(struct remote *remote);
bool remote_receive(struct remote *remote, struct shim_response *response);
bool remote_send(struct remote *remote, const struct shim_request *request);