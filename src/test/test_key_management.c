#include "../key_management.h"

void
test_derive_ratchet_keys() {
    key_manager_t km;
    init_key_manager(km);
    uint8_t shared[56] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    derive_ratchet_keys(km, shared, sizeof(shared));
    derive_ratchet_keys(km, shared, sizeof(shared));

    gcry_md_hd_t sha3_512;
    ratchet_t next_ratchet;
    uint8_t magic[3] = {0x00, 0x01, 0x02};
    gcry_md_open(&sha3_512, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
    gcry_md_write(sha3_512, shared, 56);
    gcry_md_write(sha3_512, &magic[0], 1);
    memcpy(next_ratchet->root_key, gcry_md_read(sha3_512, 0), sizeof(root_key_t));
    gcry_md_close(sha3_512);

    otrv4_assert_cmpmem(next_ratchet->root_key, km->current->root_key, sizeof(root_key_t));
    otrv4_assert_cmpmem(next_ratchet->root_key, km->head->next->next->root_key, sizeof(root_key_t));
    otrv4_assert(km->current == km->head->next->next);
    otrv4_assert(km->current != km->head->next);
}
