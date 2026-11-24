/* From LedgerHQ/app-btec (Apache-2.0). Modified 2026: signing key only. */

#include <string.h>

#include "lcx_math.h"

#include "io.h"

#include "../sw.h"
#include "bls_common.h"
#include "get_pk.h"

int handler_get_signing_pk(uint32_t index) {
    uint32_t path[] = {PURPOSE, COIN_TYPE, index, 0, 0};
    cx_ecfp_384_private_key_t sk;
    cx_ecfp_384_public_key_t pk;
    uint8_t y_flag = 0;
    uint8_t tmp[96];
    uint8_t bls_field[48];
    int cmp_diff = 0;
    cx_err_t ret;

    memset(tmp, 0, sizeof(tmp));
    ret = get_bls_sk(path, 5, &sk);
    if (ret == CX_OK) {
        ret = cx_ecfp_generate_pair_no_throw(CX_CURVE_BLS12_381_G1,
                                             (cx_ecfp_public_key_t *) &pk,
                                             (cx_ecfp_private_key_t *) &sk,
                                             1);
    }
    explicit_bzero(&sk, sizeof(sk));
    /* Compressed form: the flag tells whether y is the larger of the two roots (2y > p). */
    tmp[47] = 2;
    if (ret == CX_OK) {
        ret = cx_math_mult_no_throw(tmp, pk.W + 1 + 48, tmp, 48);
    }
    if (ret == CX_OK) {
        ret = cx_ecdomain_parameter(CX_CURVE_BLS12_381_G1,
                                    CX_CURVE_PARAM_Field,
                                    bls_field,
                                    sizeof(bls_field));
    }
    if (ret == CX_OK) {
        ret = cx_math_cmp_no_throw(tmp + 48, bls_field, 48, &cmp_diff);
    }
    if (ret != CX_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    if (cmp_diff > 0) {
        y_flag = 0x20;
    }
    pk.W[1] &= 0x1f;
    pk.W[1] |= 0x80 | y_flag;
    return io_send_response_pointer(pk.W + 1, 48, SW_OK);
}
