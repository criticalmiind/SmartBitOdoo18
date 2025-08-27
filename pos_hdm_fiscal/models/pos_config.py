
# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)

class PosConfig(models.Model):
    _inherit = 'pos.config'

    hdm_enabled = fields.Boolean(string='Enable HDM Fiscal Register', default=False)
    hdm_simulate = fields.Boolean(string='Simulation Mode', default=False,
                                  help='If enabled, device operations are simulated (for testing).')
    hdm_ip = fields.Char(string='HDM IP Address')
    hdm_port = fields.Integer(string='HDM TCP Port', default=7777)
    hdm_password = fields.Char(string='HDM Password')
    hdm_cashier_id = fields.Char(string='HDM Cashier ID')
    hdm_cashier_pin = fields.Char(string='HDM Cashier PIN')
    hdm_print_locally = fields.Boolean(string='HDM Prints Physical Receipt', default=True,
        help='If disabled, Odoo prints the receipt including HDM fiscal fields returned by the device.')

    def action_hdm_clear_session(self):
        self.ensure_one()
        self.env['pos.hdm.session']._clear_session(self.id)
        return True

    def action_hdm_test_connection(self):
        self.ensure_one()
        if not self.hdm_enabled:
            raise UserError(_('Enable HDM first.'))
        client = self.env['pos.hdm.session']._get_client(self.id, simulate=self.hdm_simulate)
        try:
            ok = client.test_connection(self)
            if not ok:
                raise UserError(_('HDM test failed. Check IP/Port/Password.'))
        except Exception as e:
            raise UserError(_('HDM test failed: %s') % (e,))
        return True
