#include "shim/lib/remote.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "shim/shared/message.h"
#include "shim/shared/buffered_fd.h"

static void cleanup_pipe(int fds[2]) {
    if (fds[0] != -1) close(fds[0]);
    if (fds[1] != -1) close(fds[1]);
}

bool remote_init(struct remote *remote) {
    int fd_stdin[2] = {-1, -1};
    int fd_stdout[2] = {-1, -1};

    remote->stdin = NULL;
    remote->stdout = NULL;
    remote->server_pid = -1;

    if (pipe(fd_stdin) == -1) {
        return false;
    }
    if (pipe(fd_stdout) == -1) {
        cleanup_pipe(fd_stdin);
        return false;
    }

    remote->server_pid = fork();
    if (remote->server_pid == -1) {
        cleanup_pipe(fd_stdin);
        cleanup_pipe(fd_stdout);
        return false;
    }

    if (remote->server_pid == 0) {
        dup2(fd_stdin[0], STDIN_FILENO);
        dup2(fd_stdout[1], STDOUT_FILENO);
        cleanup_pipe(fd_stdin);
        cleanup_pipe(fd_stdout);

        char *server = getenv("PAM_SHIM_SERVER");
        if (!server) {
            #ifndef PAM_SHIM_DEFAULT_SERVER
            #define PAM_SHIM_DEFAULT_SERVER "pam_shim_server"
            #endif
            server = PAM_SHIM_DEFAULT_SERVER;
        }

        execlp(server, "pam_shim_server", NULL);
        _exit(1);
    }

    close(fd_stdin[0]);
    close(fd_stdout[1]);

    remote->stdin = buffered_fd_new(fd_stdin[1]);
    if (!remote->stdin) {
        close(fd_stdin[1]);
        close(fd_stdout[0]);
        kill(remote->server_pid, SIGTERM);
        waitpid(remote->server_pid, NULL, 0);
        remote->server_pid = -1;
        return false;
    }

    remote->stdout = buffered_fd_new(fd_stdout[0]);
    if (!remote->stdout) {
        close(fd_stdout[0]);
        buffered_fd_close(remote->stdin);
        free(remote->stdin);
        remote->stdin = NULL;
        kill(remote->server_pid, SIGTERM);
        waitpid(remote->server_pid, NULL, 0);
        remote->server_pid = -1;
        return false;
    }

    return true;
}

bool remote_close(struct remote *remote) {
    if (remote->stdin) {
        buffered_fd_close(remote->stdin);
        free(remote->stdin);
        remote->stdin = NULL;
    }
    if (remote->stdout) {
        buffered_fd_close(remote->stdout);
        free(remote->stdout);
        remote->stdout = NULL;
    }
    if (remote->server_pid == -1) {
        return false;
    }

    int status;
    if (waitpid(remote->server_pid, &status, 0) == -1) {
        remote->server_pid = -1;
        return false;
    }

    remote->server_pid = -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool remote_receive(struct remote *remote, struct shim_response *response) {
    return shim_response_read(remote->stdout, response);
}
bool remote_send(struct remote *remote, const struct shim_request *request) {
    return shim_request_write(remote->stdin, request);
}