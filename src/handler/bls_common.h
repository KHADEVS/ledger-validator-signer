#ifndef BLS_COMMON_H_
#define BLS_COMMON_H_

#include <stdint.h>
#include "lcx_ecfp.h"

#define PURPOSE   12381
#define COIN_TYPE 3600

cx_err_t get_bls_sk(const uint32_t *path, uint8_t path_length, cx_ecfp_384_private_key_t *sk);

/* How many signing keys the device derives: m/12381/3600/key/0/0, key below this number. */
#define DERIVED_KEYS 32

/*
 * The signing key number `key`. Deriving it (EIP-2333) costs thousands of hashes, so it is done
 * once and the result stays in the device's memory until the app closes.
 */
cx_err_t get_signing_sk(uint32_t key, cx_ecfp_384_private_key_t *sk);
void forget_signing_sks(void);

#endif  // BLS_COMMON_H_
