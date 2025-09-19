# -*- coding: utf-8 -*-
{
     "name" : "Hotel Dashboard ",
    "version" : "18.0.1.1",
    "author" : "Pragmatic",
    'website': 'http://pragtech.co.in/',
    "category" : "Generic Modules/Hotel Dashboard",
    'summary': "Short (1 phrase/line) summary of the module's purpose",

    'description': """
Long description of module's purpose
    

This module is upgraded by the following:
Shawal Ahmad Mohmand
Facebook: https://facebook.com/kkamaljan
GitHub: https://github.com/criticalmiind
Google: https://www.google.com/search?q=shawal+ahmad+mohmand
Contact: +92 304 9758182
Email: kamaljankamal4@gmail.com
""",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/15.0/odoo/addons/base/data/ir_module_category_data.xml
    # for the full list
    

    # any module necessary for this one to work correctly
    'depends': ['base','hotel_management'],

    # always loaded
    'data': [
        # 'security/ir.model.access.csv',
        'views/hotel_dashboard_views.xml',
    ],
    # only loaded in demonstration mode
    'demo': [
        'demo/demo.xml',
    ],
    'assets': {
        'web.assets_backend': [
            '/hotel_dashboard/static/src/view/calendar/calendar_controller.xml',
            '/hotel_dashboard/static/src/view/calendar/calendar_controller.js',
        ],
    },
}

