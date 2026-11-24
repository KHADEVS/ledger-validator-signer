#pragma once

/* Name of the network being enabled, or its genesis_validators_root in hex. */
extern char g_network_str[2 + 64 + 1];

void ui_display_enable(void);
