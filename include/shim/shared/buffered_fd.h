#pragma once
#include <stdbool.h>
#include <stddef.h>

struct buffered_fd;

struct buffered_fd *buffered_fd_new(int fd);
void buffered_fd_close(struct buffered_fd *bfd);

bool buffered_fd_read_exact(struct buffered_fd *bfd, void *buf, size_t len);
bool buffered_fd_write_exact(struct buffered_fd *bfd, void *buf, size_t len);
bool buffered_fd_flush(struct buffered_fd *bfd);