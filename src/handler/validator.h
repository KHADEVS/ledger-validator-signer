#pragma once

#include <stdbool.h>
#include <stdint.h>

/* key 4 (big endian) | fork version 4 | genesis_validators_root 32 */
#define DUTY_HEADER       40
#define ATTESTATION_SIZE  128
#define BLOCK_HEADER_SIZE 112

int handler_enable(const uint8_t genesis_root[32]);
void enable_choice(bool approved);
int handler_sign_attestation(const uint8_t *data, const uint8_t *share);
int handler_sign_block(const uint8_t *data);
int handler_get_mark(uint32_t key);

#ifdef TEST_BUILD
int handler_import_mark(const uint8_t *data);
int handler_reset(void);
#endif
