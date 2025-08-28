
# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # Bridge fields to per-terminal settings on pos.config
    hdm_enabled = fields.Boolean(related='pos_config_id.hdm_enabled', readonly=False)
    hdm_simulate = fields.Boolean(related='pos_config_id.hdm_simulate', readonly=False)
    hdm_ip = fields.Char(related='pos_config_id.hdm_ip', readonly=False)
    hdm_port = fields.Integer(related='pos_config_id.hdm_port', readonly=False)
    hdm_password = fields.Char(related='pos_config_id.hdm_password', readonly=False)
    hdm_cashier_id = fields.Char(related='pos_config_id.hdm_cashier_id', readonly=False)
    hdm_cashier_pin = fields.Char(related='pos_config_id.hdm_cashier_pin', readonly=False)
    hdm_print_locally = fields.Boolean(related='pos_config_id.hdm_print_locally', readonly=False)
    # Last test diagnostics (related for display)
    hdm_last_test_ok = fields.Boolean(related='pos_config_id.hdm_last_test_ok', readonly=True)
    hdm_last_test_at = fields.Datetime(related='pos_config_id.hdm_last_test_at', readonly=True)
    hdm_last_test_message = fields.Char(related='pos_config_id.hdm_last_test_message', readonly=True)
    hdm_last_machine_info = fields.Text(related='pos_config_id.hdm_last_machine_info', readonly=True)

    def action_hdm_test_connection(self):
        self.ensure_one()
        if not self.pos_config_id:
            raise UserError(_('Select a POS to configure.'))
        return self.pos_config_id.action_hdm_test_connection()

    def action_hdm_clear_session(self):
        self.ensure_one()
        if not self.pos_config_id:
            raise UserError(_('Select a POS to configure.'))
        return self.pos_config_id.action_hdm_clear_session()
