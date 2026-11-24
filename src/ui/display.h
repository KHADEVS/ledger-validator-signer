#pragma once

#include <stdbool.h>
#include <stdint.h>

/* What the device asks the user to approve: two lines naming the action, then one or two fields. */
extern char g_confirm_action[2][16];
extern char g_confirm_title[2][12];
extern char g_confirm_text[2][2 + 64 + 1];

/* Shows the screens, then calls `done` with the user's answer. */
void ui_confirm(uint8_t fields, void (*done)(bool approved));
