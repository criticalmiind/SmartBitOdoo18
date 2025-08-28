/** @odoo-module **/
import { _t } from "@web/core/l10n/translation";
import { patch } from "@web/core/utils/patch";
import { PaymentScreen } from "@point_of_sale/app/screens/payment_screen/payment_screen";
import { AlertDialog } from "@web/core/confirmation_dialog/confirmation_dialog";
import { PosOrder } from "@point_of_sale/app/models/pos_order"; // Odoo 18 path

patch(PaymentScreen.prototype, {
  // https://github.com/odoo/odoo/blob/18.0/addons/point_of_sale/static/src/app/screens/payment_screen/payment_screen.js#L291
  async _finalizeValidation() {
    console.log("_finalizeValidation this", this);
    console.log("_finalizeValidation this.pos", this.pos);
    console.log("_finalizeValidation this.env.pos", this.env.pos);
    
    const config = this.pos.config || {};
    // const config = this.currentOrder.config || {};
    if (!config.hdm_enabled) {
      return super._finalizeValidation(...arguments);
    }

    try {
      const orm = this.env.services.orm;     // ← correct service in v18
      const order = this.pos.get_order();
      const payload = order.serialize({ orm: true });
      const result = await orm.call(
        "pos.order",
        "hdm_print_receipt",
        [config.id, payload],
        { context: this.pos?.context || {} }
      );
      // Attach fiscal data if present, regardless of print location
      if (result && typeof result === 'object') {
        const hasFiscal = !!(result.fiscal_number || result.verification_number || result.rseq || result.qr || result.crn);
        if (hasFiscal) {
          order.hdm_fiscal = result;
        }
      }
    } catch (err) {
      const msg = String(err);
      this.dialog.add(AlertDialog, {
        title: _t("HDM Fiscalization Failed"),
        body: _t(`Unable to fiscalize receipt. Please try again.\n${msg}`),
      });
      return super._finalizeValidation(...arguments);
    }
    await super._finalizeValidation(...arguments);
  }
});


patch(PosOrder.prototype, {
  init_from_JSON(json) {
    super.init_from_JSON(...arguments);
    this.hdm_fiscal = json?.hdm_fiscal || null;  // restore on reload
  },
  export_as_JSON() {
    const json = super.export_as_JSON(...arguments);
    if (this.hdm_fiscal) json.hdm_fiscal = this.hdm_fiscal; // persist to backend
    return json;
  },
  export_for_printing() {
    const data = super.export_for_printing(...arguments);
    if (this.hdm_fiscal) data.hdm_fiscal = this.hdm_fiscal; // for receipt
    return data;
  },
});
