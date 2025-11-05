#include "shim/shared/util.h"

#include <stdlib.h>
#include <security/pam_appl.h>

void free_responses(struct pam_response *responses, size_t count) {
    if (!responses) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        if (responses[i].resp) free(responses[i].resp);
    }
    free(responses);
}