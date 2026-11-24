#ifdef HAVE_BAGL

#include "ux.h"

#include "../handler/validator.h"
#include "display.h"
#include "menu.h"

static void choice(bool approved) {
    enable_choice(approved);
    ui_menu_main();
}

UX_STEP_NOCB(ux_enable_review_step, pnn, {&C_icon_eye, "Enable", "auto signing"});
UX_STEP_NOCB(ux_enable_network_step, bnnn_paging, {.title = "Network", .text = g_network_str});
UX_STEP_CB(ux_enable_approve_step, pb, choice(true), {&C_icon_validate_14, "Approve"});
UX_STEP_CB(ux_enable_reject_step, pb, choice(false), {&C_icon_crossmark, "Reject"});

UX_FLOW(ux_enable_flow,
        &ux_enable_review_step,
        &ux_enable_network_step,
        &ux_enable_approve_step,
        &ux_enable_reject_step);

void ui_display_enable(void) {
    ux_flow_init(0, ux_enable_flow, NULL);
}

#endif
