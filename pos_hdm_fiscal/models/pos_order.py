
# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)

class PosOrder(models.Model):
    _inherit = 'pos.order'

    hdm_fiscal_number = fields.Char(string='HDM Fiscal Number')
    hdm_rseq = fields.Integer(string='HDM Receipt Sequence')
    hdm_verification_number = fields.Char(string='HDM Verification Number')
    hdm_qr_code = fields.Text(string='HDM QR (base64)')
    hdm_crn = fields.Char(string='HDM CRN/RN')

    @api.model
    def _get_config(self, pos_config_id):
        config = self.env['pos.config'].browse(pos_config_id)
        if not config or not config.exists():
            raise UserError(_('POS config not found.'))
        if not config.hdm_enabled:
            raise UserError(_('HDM not enabled for this POS.'))
        return config

    @api.model
    def hdm_print_receipt(self, pos_config_id, order_payload):
        config = self._get_config(pos_config_id)
        session_mgr = self.env['pos.hdm.session']
        client = session_mgr._get_client(config.id, simulate=config.hdm_simulate)

        with session_mgr._acquire_lock(config.id):
            client.ensure_login(config)
            resp = client.print_receipt(config, order_payload)
            if not resp.get('ok'):
                raise UserError(resp.get('message', _('Device returned an error.')))
            # Only return structured fiscal data if present; otherwise the
            # device likely acknowledged without a payload (physical print).
            if resp.get('fiscal_number') or resp.get('qr_base64') or resp.get('verification_number'):
                return {
                    'fiscal_number': resp.get('fiscal_number'),
                    'verification_number': resp.get('verification_number'),
                    'rseq': resp.get('rseq'),
                    'crn': resp.get('crn'),
                    'qr': resp.get('qr_base64'),
                }
            # Fallback: acknowledge success without structured payload
            return {'ok': True}

    @api.model
    def hdm_print_return_receipt(self, pos_config_id, original_order_id, return_payload):
        config = self._get_config(pos_config_id)
        original = self.browse(original_order_id)
        if not original.exists():
            raise UserError(_('Original order not found.'))
        if not original.hdm_crn or not original.hdm_rseq:
            raise UserError(_('Original order lacks HDM data (CRN/RSEQ).'))

        session_mgr = self.env['pos.hdm.session']
        client = session_mgr._get_client(config.id, simulate=config.hdm_simulate)

        with session_mgr._acquire_lock(config.id):
            client.ensure_login(config)
            resp = client.print_return_receipt(config, original, return_payload)
            if not resp.get('ok'):
                raise UserError(resp.get('message', _('Device returned an error.')))
            if resp.get('fiscal_number') or resp.get('qr_base64') or resp.get('verification_number'):
                return {
                    'fiscal_number': resp.get('fiscal_number'),
                    'verification_number': resp.get('verification_number'),
                    'rseq': resp.get('rseq'),
                    'crn': resp.get('crn'),
                    'qr': resp.get('qr_base64'),
                }
            return {'ok': True}

    @api.model
    def hdm_cash_in_out(self, pos_config_id, amount, is_cashin, description=None):
        config = self._get_config(pos_config_id)
        session_mgr = self.env['pos.hdm.session']
        client = session_mgr._get_client(config.id, simulate=config.hdm_simulate)
        with session_mgr._acquire_lock(config.id):
            client.ensure_login(config)
            resp = client.cash_in_out(config, amount, is_cashin, description or '')
            if not resp.get('ok'):
                raise UserError(resp.get('message', _('Device returned an error.')))
            return True

    @api.model
    def _order_fields(self, ui_order):
        vals = super()._order_fields(ui_order)
        hdm = ui_order.get('hdm_fiscal') or {}
        if hdm:
            vals.update({
                'hdm_fiscal_number': hdm.get('fiscal_number'),
                'hdm_rseq': hdm.get('rseq') or 0,
                'hdm_verification_number': hdm.get('verification_number'),
                'hdm_qr_code': hdm.get('qr'),
                'hdm_crn': hdm.get('crn'),
            })
        return vals
