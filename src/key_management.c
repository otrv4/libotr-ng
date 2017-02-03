#include <stdlib.h>
#include <string.h>

#include "ed448.h"
#include "gcrypt.h"
#include "key_management.h"

void
append_ratchet(key_manager_t manager, ratchet_t r)
{
    manager->current->next = r;
    manager->current = r;
}

void
init_key_manager(key_manager_t manager){
    ratchet_t head;
    manager->head = head;
    manager->current = head;
}

void
derive_ratchet_keys(key_manager_t manager, const uint8_t *shared)
{
    gcry_md_hd_t sha3_512;
    ratchet_t next_ratchet;
    uint8_t magic[3] = {0x00, 0x01, 0x02};
    gcry_md_open(&sha3_512, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
    gcry_md_write(sha3_512, shared, sizeof(shared));
    gcry_md_write(sha3_512, &magic[0], 1);
    gcry_md_extract(sha3_512, GCRY_MD_SHA3_512, next_ratchet->root_key, sizeof(root_key_t));

    gcry_md_reset(sha3_512);
    gcry_md_write(sha3_512, shared, sizeof(shared));
    gcry_md_write(sha3_512, &magic[1], 1);
    gcry_md_extract(sha3_512, GCRY_MD_SHA3_512, next_ratchet->chain_keys_a[0], sizeof(root_key_t));

    gcry_md_reset(sha3_512);
    gcry_md_write(sha3_512, shared, sizeof(shared));
    gcry_md_write(sha3_512, &magic[2], 1);
    gcry_md_extract(sha3_512, GCRY_MD_SHA3_512, next_ratchet->chain_keys_b[0], sizeof(root_key_t));
    append_ratchet(manager, next_ratchet);
}
