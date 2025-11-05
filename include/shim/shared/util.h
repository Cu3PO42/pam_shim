#pragma once
#include <stddef.h>

struct pam_response;
void free_responses(struct pam_response *responses, size_t count);
