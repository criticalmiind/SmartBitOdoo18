
# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase

class TestHDMCrypto(TransactionCase):
    def test_imports(self):
        from Crypto.Cipher import DES3  # noqa
        self.assertTrue(True)
