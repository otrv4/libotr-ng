#include "../key_management.h"

void
test_derive_ratchet_keys() {
    key_manager_t km;
    uint8_t shared[56] = "hello";
    init_key_manager(km);
    derive_ratchet_keys(km, shared);
}
