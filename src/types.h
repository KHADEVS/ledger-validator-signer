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
    SIGN_AGGREGATION_SLOT = 0x27,
    SIGN_RANDAO = 0x28,
    SIGN_SYNC_MESSAGE = 0x29,
    SIGN_SYNC_SELECTION = 0x2A,
    STREAM_BEGIN = 0x2C,
    STREAM_BITS = 0x2D,
    STREAM_END = 0x2E,
    SIGN_EXIT = 0x30,
    SET_FEE = 0x31,
    SIGN_REGISTRATION = 0x32,
    GET_IMPORT_KEY = 0x33,
    IMPORT_SHARE = 0x34,
#ifdef TEST_BUILD
    TEST_IMPORT_MARK = 0x24,
    TEST_RESET = 0x25,
    TEST_SIGN_WITH_SHARE = 0x26,
#endif
} command_e;
