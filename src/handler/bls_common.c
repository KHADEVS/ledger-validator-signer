/* From LedgerHQ/app-btec (Apache-2.0). */

#include <string.h>

#include "os_io_seproxyhal.h"
#include "os_seed.h"

#include "bls_common.h"

cx_err_t get_bls_sk(const uint32_t *path, uint8_t path_length, cx_ecfp_384_private_key_t *sk) {
    uint8_t sk_data[48];
    cx_err_t ret;

    memset(sk_data, 0, 16);
    io_seproxyhal_io_heartbeat();
    ret = os_derive_eip2333_no_throw(CX_CURVE_BLS12_381_G1, path, path_length, sk_data + 16);
    io_seproxyhal_io_heartbeat();
    if (ret == CX_OK) {
        ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_BLS12_381_G1,
                                                sk_data,
                                                sizeof(sk_data),
                                                (cx_ecfp_private_key_t *) sk);
    }
    memset(sk_data, 0, sizeof(sk_data));
    return ret;
}

static uint8_t g_sk[DERIVED_KEYS][32];
static uint32_t g_sk_known; /* bit n: g_sk[n] holds the key number n */

cx_err_t get_signing_sk(uint32_t key, cx_ecfp_384_private_key_t *sk) {
    uint8_t raw[48];
    cx_err_t ret;

    if (key >= DERIVED_KEYS) {
        return CX_INVALID_PARAMETER;
    }
    if ((g_sk_known & (1u << key)) == 0) {
        const uint32_t path[] = {PURPOSE, COIN_TYPE, key, 0, 0};
        io_seproxyhal_io_heartbeat();
        ret = os_derive_eip2333_no_throw(CX_CURVE_BLS12_381_G1, path, 5, g_sk[key]);
        io_seproxyhal_io_heartbeat();
        if (ret != CX_OK) {
            explicit_bzero(g_sk[key], sizeof(g_sk[key]));
            return ret;
        }
        g_sk_known |= 1u << key;
    }
    memset(raw, 0, 16);
    memcpy(raw + 16, g_sk[key], 32);
    ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_BLS12_381_G1,
                                            raw,
                                            sizeof(raw),
                                            (cx_ecfp_private_key_t *) sk);
    explicit_bzero(raw, sizeof(raw));
    return ret;
}

void forget_signing_sks(void) {
    explicit_bzero(g_sk, sizeof(g_sk));
    g_sk_known = 0;
}
