
# -*- coding: utf-8 -*-
from odoo import api, fields, models
import threading

class PosHDMSession(models.AbstractModel):
    _name = 'pos.hdm.session'
    _description = 'POS HDM Session Manager'

    _clients = {}
    _locks = {}

    def _get_lock(self, pos_config_id):
        if pos_config_id not in self._locks:
            self._locks[pos_config_id] = threading.Lock()
        return self._locks[pos_config_id]

    def _acquire_lock(self, pos_config_id):
        return self._get_lock(pos_config_id)

    def _get_client(self, pos_config_id, simulate=False):
        from ..services.hdm_client import HDMClient
        key = (pos_config_id, simulate)
        client = self._clients.get(key)
        if client is None or client.is_closed():
            client = HDMClient(simulate=simulate)
            self._clients[key] = client
        return client

    def _clear_session(self, pos_config_id):
        for key in list(self._clients.keys()):
            if key[0] == pos_config_id:
                try:
                    self._clients[key].close()
                except Exception:
                    pass
                self._clients.pop(key, None)
        return True
