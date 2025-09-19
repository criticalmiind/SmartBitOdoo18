# -*- encoding: utf-8 -*-
{
    "name": "Hotel Housekeeping Management",
    "version": "18.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    'website': 'http://pragtech.co.in/',
    "category": "Generic Modules/Hotel Housekeeping",
    "description": """
    Module for Hotel/Hotel Housekeeping. You can manage:
    * Housekeeping process
    * Housekeeping history room wise

      Different reports are also provided, mainly for hotel statistics.
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["hotel"],
    "data": [
        # "hotel_housekeeping_workflow.xml",  # workflow does not exist in odoo11
        # "data/hotel_housekeeping_data.xml",
        "views/hotel_housekeeping_view.xml",
        "security/ir.model.access.csv",
    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
