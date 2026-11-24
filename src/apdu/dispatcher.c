/* From LedgerHQ/app-btec (Apache-2.0). Modified 2026: validator commands, no host-given root. */

#include <stdbool.h>
#include <stdint.h>

#include "buffer.h"
#include "io.h"

#include "../constants.h"
#include "../globals.h"
#include "../handler/get_app_name.h"
#include "../handler/get_pk.h"
#include "../handler/get_version.h"
#include "../handler/validator.h"
#include "../sw.h"
#include "../types.h"
#include "dispatcher.h"

static bool size_is(const command_t *cmd, int size) {
    return cmd->lc == size;
}

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }
    if (cmd->p1 != 0 || cmd->p2 != 0) {
        return io_send_sw(SW_WRONG_P1P2);
    }

    switch (cmd->ins) {
        case GET_VERSION:
            return handler_get_version();

        case GET_APP_NAME:
            return handler_get_app_name();

        case GET_SIGNING_PK:
            return size_is(cmd, 4) ? handler_get_signing_pk(U4BE(cmd->data, 0))
                                   : io_send_sw(SW_WRONG_DATA_LENGTH);

        case ENABLE:
            return size_is(cmd, 32) ? handler_enable(cmd->data) : io_send_sw(SW_WRONG_DATA_LENGTH);

        case SIGN_ATTESTATION:
            return size_is(cmd, DUTY_HEADER + ATTESTATION_SIZE)
                       ? handler_sign_attestation(cmd->data, NULL)
                       : io_send_sw(SW_WRONG_DATA_LENGTH);

        case SIGN_BLOCK:
            return size_is(cmd, DUTY_HEADER + BLOCK_HEADER_SIZE) ? handler_sign_block(cmd->data)
                                                                 : io_send_sw(SW_WRONG_DATA_LENGTH);

        case GET_MARK:
            return size_is(cmd, 4) ? handler_get_mark(U4BE(cmd->data, 0))
                                   : io_send_sw(SW_WRONG_DATA_LENGTH);

#ifdef TEST_BUILD
        case TEST_IMPORT_MARK:
            return size_is(cmd, 62) ? handler_import_mark(cmd->data)
                                    : io_send_sw(SW_WRONG_DATA_LENGTH);

        case TEST_RESET:
            return handler_reset();

        case TEST_SIGN_WITH_SHARE:
            return size_is(cmd, 32 + DUTY_HEADER + ATTESTATION_SIZE)
                       ? handler_sign_attestation(cmd->data + 32, cmd->data)
                       : io_send_sw(SW_WRONG_DATA_LENGTH);
#endif

        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
