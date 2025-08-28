
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
    hdm_print_locally = fields.Boolean(string='HDM Prints Physical Receipt', default=True,
        help='If disabled, Odoo prints the receipt including HDM fiscal fields returned by the device.')

    # Departments fetched from device, and the selected department for service
    hdm_department_id = fields.Many2one(
        'pos.hdm.department',
        string='HDM Department',
        domain="[('pos_config_id', '=', id)]",
        ondelete='set null',
        help='Department to send to HDM when printing receipts. Fetched from device on Test Connection.'
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

            # Fetch operators and departments from device. If the device
            # doesn't support this call or only ACKs, don't fail the test.
            try:
                deps = client.get_ops_deps(self)
                dep_list = deps.get('departments') or []
                # Only replace local list if we actually received departments
                if dep_list:
                    # Clear selection to avoid FK constraint, then remove existing
                    self.hdm_department_id = False
                    self.env['pos.hdm.department'].search([('pos_config_id', '=', self.id)]).unlink()
                    # Create new ones
                    vals_list = []
                    for d in dep_list:
                        did = d.get('id')
                        typ = d.get('type')
                        if isinstance(did, str) and did.isdigit():
                            did = int(did)
                        if isinstance(typ, str) and typ.isdigit():
                            typ = int(typ)
                        if isinstance(did, int) and did > 0:
                            vals_list.append({
                                'pos_config_id': self.id,
                                'dept_id': did,
                                'name': d.get('name') or '',
                                'type': typ or 0,
                            })
                    if vals_list:
                        created = self.env['pos.hdm.department'].create(vals_list)
                        # Auto-select if only one
                        if len(created) == 1:
                            self.hdm_department_id = created.id
            except Exception as dep_e:
                raise UserError(_('HDM department fetch failed: %s') % (dep_e,))
                _logger.warning('HDM department fetch failed: %s', dep_e)
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
