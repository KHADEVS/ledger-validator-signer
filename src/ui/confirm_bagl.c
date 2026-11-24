#ifdef HAVE_BAGL

#include "ux.h"

#include "display.h"
#include "menu.h"

char g_confirm_action[2][16];
char g_confirm_title[2][12];
char g_confirm_text[2][2 + 64 + 1];

static void (*g_done)(bool approved);

static void choice(bool approved) {
    void (*done)(bool) = g_done;
    g_done = NULL;
    if (done != NULL) {
        done(approved);
    }
    ui_menu_main();
}

UX_STEP_NOCB(ux_confirm_review_step, pnn, {&C_icon_eye, g_confirm_action[0], g_confirm_action[1]});
UX_STEP_NOCB(ux_confirm_first_step,
             bnnn_paging,
             {.title = g_confirm_title[0], .text = g_confirm_text[0]});
UX_STEP_NOCB(ux_confirm_second_step,
             bnnn_paging,
             {.title = g_confirm_title[1], .text = g_confirm_text[1]});
UX_STEP_CB(ux_confirm_approve_step, pb, choice(true), {&C_icon_validate_14, "Approve"});
UX_STEP_CB(ux_confirm_reject_step, pb, choice(false), {&C_icon_crossmark, "Reject"});

UX_FLOW(ux_confirm_one_flow,
        &ux_confirm_review_step,
        &ux_confirm_first_step,
        &ux_confirm_approve_step,
        &ux_confirm_reject_step);

UX_FLOW(ux_confirm_two_flow,
        &ux_confirm_review_step,
        &ux_confirm_first_step,
        &ux_confirm_second_step,
        &ux_confirm_approve_step,
        &ux_confirm_reject_step);

void ui_confirm(uint8_t fields, void (*done)(bool approved)) {
    g_done = done;
    ux_flow_init(0, fields == 2 ? ux_confirm_two_flow : ux_confirm_one_flow, NULL);
}

#endif
