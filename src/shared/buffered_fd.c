#include "shim/shared/buffered_fd.h"

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

struct buffered_fd {
    int fd;
    char buffer[4096];
    size_t buf_used;
    size_t buf_pos;
};

struct buffered_fd *buffered_fd_new(int fd) {
    struct buffered_fd *bfd = malloc(sizeof(struct buffered_fd));
    if (!bfd) return NULL;
    bfd->fd = fd;
    bfd->buf_used = 0;
    bfd->buf_pos = 0;
    return bfd;
}

void buffered_fd_close(struct buffered_fd *bfd) {
    if (bfd) {
        close(bfd->fd);
    }
}

bool buffered_fd_read_exact(struct buffered_fd *bfd, void *buf, size_t len) {
    size_t total_read = 0;
    while (total_read < len) {
        if (bfd->buf_pos >= bfd->buf_used) {
            ssize_t n = read(bfd->fd, bfd->buffer, sizeof(bfd->buffer));
            if (n <= 0) return false;
            bfd->buf_used = n;
            bfd->buf_pos = 0;
        }
        size_t to_copy = bfd->buf_used - bfd->buf_pos;
        if (to_copy > len - total_read) {
            to_copy = len - total_read;
        }
        memcpy((char *)buf + total_read, bfd->buffer + bfd->buf_pos, to_copy);
        bfd->buf_pos += to_copy;
        total_read += to_copy;
    }
    return true;
}

bool buffered_fd_flush(struct buffered_fd *bfd) {
    size_t total_written = 0;
    while (total_written < bfd->buf_used) {
        ssize_t n = write(bfd->fd, bfd->buffer + total_written, bfd->buf_used - total_written);
        if (n <= 0) return false;
        total_written += (size_t)n;
    }
    bfd->buf_used = 0;
    bfd->buf_pos = 0;
    return true;
}

bool buffered_fd_write_exact(struct buffered_fd *bfd, void *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        size_t space = sizeof(bfd->buffer) - bfd->buf_used;
        if (space == 0) {
            if (!buffered_fd_flush(bfd)) return false;
            space = sizeof(bfd->buffer);
        }
        size_t to_copy = len - written;
        if (to_copy > space) to_copy = space;
        memcpy(bfd->buffer + bfd->buf_used, (const char *)buf + written, to_copy);
        bfd->buf_used += to_copy;
        written += to_copy;
    }
    return true;
}
