
# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase

class TestHDMClient(TransactionCase):
    def setUp(self):
        super().setUp()
        self.client = self.env['pos.hdm.session']._get_client(999, simulate=True)

    def test_sim_ping(self):
        class Dummy: pass
        d = Dummy()
        d.hdm_password = 'x'
        d.hdm_ip = '127.0.0.1'
        d.hdm_port = 7777
        ok = self.client.test_connection(d)
        self.assertTrue(ok)
