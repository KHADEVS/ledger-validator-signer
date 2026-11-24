#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* key 4 (big endian) | fork version 4 | genesis_validators_root 32 */
#define DUTY_HEADER       40
#define ATTESTATION_SIZE  128
#define BLOCK_HEADER_SIZE 112

/* First byte after the header of STREAM_BEGIN. */
#define STREAM_AGGREGATE         0
#define STREAM_AGGREGATE_ELECTRA 1
#define STREAM_CONTRIBUTION      2
#define STREAM_AGGREGATE_GLOAS   3

int handler_enable(const uint8_t genesis_root[32]);
int handler_sign_attestation(const uint8_t *data, const uint8_t *share);
int handler_sign_block(const uint8_t *data);
int handler_get_mark(uint32_t key);
int handler_sign_small(uint8_t ins, const uint8_t *data);
int handler_stream_begin(const uint8_t *data, size_t len);
int handler_stream_bits(const uint8_t *data, size_t len);
int handler_stream_end(const uint8_t *data);
int handler_sign_exit(const uint8_t *data);
int handler_set_fee(const uint8_t *data);
int handler_sign_registration(const uint8_t *data);

#ifdef TEST_BUILD
int handler_import_mark(const uint8_t *data);
int handler_reset(void);
#endif
