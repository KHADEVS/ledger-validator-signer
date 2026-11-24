/* From LedgerHQ/app-btec (Apache-2.0). Modified 2026: no About submenu. */

#ifdef HAVE_BAGL

#include "glyphs.h"
#include "os.h"
#include "ux.h"

#include "../globals.h"
#include "menu.h"

UX_STEP_NOCB(ux_menu_ready_step, pnn, {&C_logo, APPNAME, "is ready"});
UX_STEP_NOCB(ux_menu_version_step, bn, {"Version", APPVERSION});
UX_STEP_NOCB(ux_menu_warning_step, bn, {"Prototype", "not for real keys"});
UX_STEP_VALID(ux_menu_exit_step, pb, os_sched_exit(-1), {&C_icon_dashboard_x, "Quit"});

UX_FLOW(ux_menu_main_flow,
        &ux_menu_ready_step,
        &ux_menu_version_step,
        &ux_menu_warning_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

void ui_menu_main(void) {
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_menu_main_flow, NULL);
}

#endif
