# -*- coding: utf-8 -*-
from odoo import api, fields, models


class PosHDMDepartment(models.Model):
    _name = 'pos.hdm.department'
    _description = 'POS HDM Department (fetched from device)'
    # _order = 'pos_config_id, dept_id'

    pos_config_id = fields.Many2one('pos.config', required=True, ondelete='cascade')
    dept_id = fields.Integer(string='Department ID', required=True)
    name = fields.Char(string='Name')
    type = fields.Integer(string='Type')

    # _sql_constraints = [
    #     ('pos_dept_unique', 'unique(pos_config_id, dept_id)', 'Department already exists for this POS.'),
    # ]

