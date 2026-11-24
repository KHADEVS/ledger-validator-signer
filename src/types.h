#pragma once

/* Command numbers (INS). */
typedef enum {
    GET_VERSION = 0x03,
    GET_APP_NAME = 0x04,
    GET_SIGNING_PK = 0x06,
    ENABLE = 0x20,
    SIGN_ATTESTATION = 0x21,
    SIGN_BLOCK = 0x22,
    GET_MARK = 0x23,
#ifdef TEST_BUILD
    TEST_IMPORT_MARK = 0x24,
    TEST_RESET = 0x25,
    TEST_SIGN_WITH_SHARE = 0x26,
#endif
} command_e;
