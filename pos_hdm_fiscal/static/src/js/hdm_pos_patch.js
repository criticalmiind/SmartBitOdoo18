
odoo.define('pos_hdm_fiscal.hdm_pos_patch', function (require) {
  'use strict';

  const Registries = require('point_of_sale.Registries');
  const PaymentScreen = require('point_of_sale.PaymentScreen');

  const HDMPatchedPaymentScreen = (PaymentScreen) => class extends PaymentScreen {
    async _finalizeValidation() {
      const config = this.env.pos.config || {};
      if (!config.hdm_enabled) {
        return super._finalizeValidation();
      }

      try {
        const order = this.env.pos.get_order();
        const payload = order.export_as_JSON();
        const result = await this.rpc({
          model: 'pos.order',
          method: 'hdm_print_receipt',
          args: [[], config.id, payload],
        });
        if (result && !config.hdm_print_locally) {
          order.hdm_fiscal = result;
        }
      } catch (err) {
        this.showPopup('ErrorPopup', {
          title: this.env._t('HDM Fiscalization Failed'),
          body: (err && err.message) || this.env._t('Unable to fiscalize receipt. Please try again.'),
        });
        return;
      }
      await super._finalizeValidation();
    }
  };

  Registries.Component.extend(PaymentScreen, HDMPatchedPaymentScreen);

  // Also extend Order to include hdm_fiscal in exported JSON so server can
  // persist it and rehydrate it when loading orders.
  const models = require('point_of_sale.models');
  const Order = models.Order;

  const PatchOrder = (Order) => class extends Order {
    constructor() {
      super(...arguments);
      this.hdm_fiscal = this.hdm_fiscal || null;
    }

    export_as_JSON() {
      const json = super.export_as_JSON(...arguments);
      if (this.hdm_fiscal) {
        json.hdm_fiscal = this.hdm_fiscal;
      }
      return json;
    }

    init_from_JSON(json) {
      super.init_from_JSON(...arguments);
      if (json.hdm_fiscal) {
        this.hdm_fiscal = json.hdm_fiscal;
      }
    }
  };
  Registries.Model.extend(Order, PatchOrder);

});
