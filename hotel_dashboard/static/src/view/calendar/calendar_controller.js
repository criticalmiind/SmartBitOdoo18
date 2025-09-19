/** @odoo-module **/

import { _t } from "@web/core/l10n/translation";
import { ConfirmationDialog } from "@web/core/confirmation_dialog/confirmation_dialog";
import { CalendarController } from "@web/views/calendar/calendar_controller";
import { FormViewDialog } from "@web/views/view_dialogs/form_view_dialog";
import { Dropdown, DropdownItem } from "@web/core/dropdown/dropdown";
import { serializeDate } from "@web/core/l10n/dates";
import { patch } from "@web/core/utils/patch";
import { useService } from "@web/core/utils/hooks";


// import { TimeOffCalendarFilterPanel } from "./filter_panel/calendar_filter_panel";
// import { TimeOffFormViewDialog } from "../view_dialog/form_view_dialog";
// import { useLeaveCancelWizard } from "../hooks";
// import { EventBus, useSubEnv } from "@odoo/owl";


console.log("-----------called rajesh files")
patch(CalendarController.prototype, {
    async setup() {
        super.setup(...arguments);
        this.today
        this.date
        this.orm = useService("orm");
        const result =  await this.orm.call("hotel.reservation", "get_data");
        this.check_in = result.check_in
        this.check_out = result.check_out
        this.total = result.total
        this.booked =result.booked
    },
    

    get check_in_request() {
        return this.check_in
    },

    get check_out_request(){
        return this.check_out
    },

    get total_available(){
        return this.total
    },

    get total_booked(){
        return this.booked
    },


    
})






