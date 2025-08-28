
# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError
import logging
import json

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
    hdm_department_id = fields.Char(string='HDM Department ID',
        help='Department identifier required by some HDM devices to determine VAT vs Non‑VAT.')
    hdm_print_locally = fields.Boolean(string='HDM Prints Physical Receipt', default=True,
        help='If disabled, Odoo prints the receipt including HDM fiscal fields returned by the device.')

    # Optional: semantic department type (for devices that use a code)
    hdm_department = fields.Selection(
        [
            ('vat', 'VAT Department'),
            ('non_vat', 'Non‑VAT Department'),
        ],
        string='HDM Department',
        default='vat',
        help='Department code sent to HDM for receipts; determines VAT handling on the device.'
    )

    # Diagnostics / last test results
    hdm_last_test_ok = fields.Boolean(string='HDM Last Test OK', readonly=True)
    hdm_last_test_at = fields.Datetime(string='HDM Last Test At', readonly=True)
    hdm_last_test_message = fields.Char(string='HDM Last Test Message', readonly=True)
    hdm_last_machine_info = fields.Text(string='HDM Last Machine Info', readonly=True)

    def action_hdm_clear_session(self):
        self.ensure_one()
        self.env['pos.hdm.session']._clear_session(self.id)
        return True

    def action_hdm_test_connection(self):
        self.ensure_one()
        if not self.hdm_enabled:
            raise UserError(_('Enable HDM first.'))
        client = self.env['pos.hdm.session']._get_client(self.id, simulate=self.hdm_simulate)
        from datetime import datetime
        try:
            result = client.test_connection(self)
            ok = bool(result) and bool(result.get('ok')) if isinstance(result, dict) else bool(result)
            info = result.get('info') if isinstance(result, dict) else {}
            # Persist outcome
            self.write({
                'hdm_last_test_ok': ok,
                'hdm_last_test_at': fields.Datetime.now(),
                'hdm_last_test_message': _('Success') if ok else _('Failed'),
                'hdm_last_machine_info': json.dumps(info or {}, ensure_ascii=False),
            })
            if not ok:
                raise UserError(_('HDM test failed. Check IP/Port/Password.'))
        except Exception as e:
            # Persist failure details
            self.write({
                'hdm_last_test_ok': False,
                'hdm_last_test_at': fields.Datetime.now(),
                'hdm_last_test_message': str(e),
                'hdm_last_machine_info': json.dumps({'error': str(e)}, ensure_ascii=False),
            })
            raise UserError(_('HDM test failed: %s') % (e,))
        return True
