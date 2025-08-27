
# -*- coding: utf-8 -*-
from odoo import http

class PosHDMController(http.Controller):
    @http.route(['/pos_hdm_fiscal/health'], type='http', auth='user', website=False)
    def health(self, **kw):
        return "ok"
