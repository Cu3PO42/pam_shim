#pragma once
#include <stddef.h>

struct pam_response;
void free_responses(struct pam_response *responses, size_t count);

void free_item(int item_type, void *item);

struct freelist;
struct freelist *freelist_append(struct freelist *list, void *item);
void freelist_free(struct freelist *list);