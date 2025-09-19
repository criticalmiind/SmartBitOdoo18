# -*- encoding: utf-8 -*-
{
    "name": "Hotel Restaurant Management ",
    "version": "18.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    'website': 'http://pragtech.co.in/',
    "category": "Generic Modules/Hotel Restaurant",
    "description": """
    Module for Hotel/Resort/Restaurant management. You can manage:
    * Configure Property
    * Restaurant Configuration
    * table reservation
    * Generate and process Kitchen Order ticket,
    * Payment
    Different reports are also provided, mainly for Restaurant.
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["base", "hotel"],
    "data": [
        "security/ir.model.access.csv",
        "wizard/hotel_restaurant_wizard.xml",
        "views/hotel_restaurant_view.xml",
        # "data/hotel_restaurant_workflow.xml",  # workflow does not exist in odoo 11
        'report/hotel_restaurant_report.xml',
        "report/restaurant_reservation_report.xml",
    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
