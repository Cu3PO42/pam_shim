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

void free_item(int item_type, void *item) {
    if (!item) {
        return;
    }
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
            free((char *)item);
            break;

        case PAM_XAUTHDATA: {
            struct pam_xauth_data *xauth = (struct pam_xauth_data *)item;
            if (xauth->data) {
                free(xauth->data);
            }
            if (xauth->name) {
                free(xauth->name);
            }
            free(xauth);
            break;
        }

        default:
            // Unknown item type, cannot free.
            break;
    }
}

struct freelist {
    void *item;
    struct freelist *next;
};

struct freelist *freelist_append(struct freelist *list, void *item) {
    struct freelist *new_node = malloc(sizeof(struct freelist));
    if (!new_node) {
        // Allocation failed, this means we might leak the memory from item later.
        return list;
    }
    new_node->item = item;
    new_node->next = list;
    return new_node;
}

void freelist_free(struct freelist *list) {
    for (struct freelist *current = list; current;) {
        struct freelist *next = current->next;
        free(current->item);
        free(current);
        current = next;
    }
}