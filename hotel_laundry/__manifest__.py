# -*- encoding: utf-8 -*-
{
    "name": "Hotel Laundry ",
    "version": "18.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    'website': 'http://pragtech.co.in/',
    "category": "Generic Modules/Hotel Laundry",
    "description": """
    Module for laundry management. You can manage:
    * Configure Property
    * Hotel Configuration
    * laundry services
    * Payment

    Different reports are also provided, mainly for hotel statistics.
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["base", "hotel", "hotel_management"],
    "data": [
        'security/hotel_laundry_security.xml',
        "security/ir.model.access.csv",
        "wizard/hotel_laundry_picking_view.xml",
        "views/hotel_laundry_view.xml",
        "views/laundry_sequence_view.xml",
        "laundry_data.xml",
    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
