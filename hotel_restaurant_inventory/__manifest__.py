# -*- encoding: utf-8 -*-

{
    "name": "Hotel Restaurant Inventory ",
    "version": "18.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    "category": "Generic Modules/Hotel Restaurant Inventory",
    "description": """
    Module for Add Concept of BOM to restaurant Module:
    * Configure Property
    * Hotel Configuration
    * Product Quantity maintainance
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["hotel_management", "mrp"],
    "data": [
        "security/ir.model.access.csv",
        "views/hotel_restaurant_inventory_view.xml",
        "views/sale_shop.xml",
    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
