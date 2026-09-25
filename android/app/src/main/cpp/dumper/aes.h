#pragma once
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void aes128_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* in, uint8_t* out, size_t len);
#ifdef __cplusplus
}
#endif
