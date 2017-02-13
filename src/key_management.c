#include <stdlib.h>
#include <string.h>

#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"

void
append_ratchet(key_manager_t manager, ratchet_t r){
    manager->current->next = r;
    manager->current = r;
}

void
init_key_manager(key_manager_t manager){
    ratchet_t *head = malloc( sizeof(ratchet_t) );
    manager->head = *head;
    manager->current = *head;
}

void
derive_ratchet_keys(key_manager_t manager, const uint8_t *shared, size_t size)
{
    gcry_md_hd_t hd;
    uint8_t magic[3] = {0x00, 0x01, 0x02};
    ratchet_t *next_ratchet = malloc( sizeof(ratchet_t) );
    gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
    gcry_md_write(hd, shared, size);
    gcry_md_write(hd, &magic[0], 1);
    memcpy(next_ratchet[0]->root_key, gcry_md_read(hd, 0), sizeof(root_key_t));

    gcry_md_close(hd);
    append_ratchet(manager, *next_ratchet);
}
