#pragma once

#include <stdint.h>

#include "cx.h"

/* Compressed public key of the signing key at `index`. */
cx_err_t derive_signing_pk(uint32_t index, uint8_t out[48]);

int handler_get_signing_pk(uint32_t index);
