#pragma once

#define SW_OK                0x9000
#define SW_DENY              0x6985
#define SW_WRONG_P1P2        0x6A86
#define SW_WRONG_DATA_LENGTH 0x6A87
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_BAD_STATE         0xB007
/* The duty conflicts with the slashing record of the key. */
#define SW_SLASHABLE   0xB101
#define SW_NOT_ENABLED 0xB102
#define SW_BAD_KEY     0xB103
#define SW_BUSY        0xB104
/* A duty in several parts that does not hold together. */
#define SW_BAD_DUTY 0xB105
/* A registration for another fee recipient or gas limit than the ones approved on the device. */
#define SW_SETTING 0xB106
