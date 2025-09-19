{
    'name': 'Hotel Management',
    'version': '18.0.0.1',
    'category': 'Services',
    'author': 'Pragmatic TechSoft Pvt Ltd.',
    'website': 'https://www.pragtech.co.in/products/odoo-verticals/odoo-openerp-hotel-management.html',
    'summary': 'Hotel Management Module for Hotel/Resort/Property management. You can manage Configure Property Hotel Configuration Check In, Check out Manage Folio',
    "description": """
Module for Hotel/Resort/Property management. You can manage:
    * Configure Property
    * Hotel Configuration
    * Check In, Check out
    * Manage Folio
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
    "depends": [
        'base',
        'stock',
        'product',
        'mrp',
        'point_of_sale',
        'web',
        'website',
        'payment',
        'hotel',
        'banquet_managment',
        'hotel_dashboard',
        'hotel_housekeeping',
        'hotel_laundry',
        'hotel_management',
        'hotel_online',
        'hotel_restaurant',
        'hotel_restaurant_inventory',
        'hotel_restaurant_pos',
        'hotel_transport_management',
        'sale_enhancement'

    ],
    'currency': 'USD',
    'price': 499,
    'images': ['static/description/img/Animated-odoo-hotel-management.gif'],
    # 'images': ['static/description/end-of-year-sale-main.jpg'],
    'live_test_url': 'https://www.pragtech.co.in/company/proposal-form.html?id=103&name=Odoo-Hotel-Management',
    'license': 'OPL-1',
    'installable': True,
    'application': False,
    'auto_install': False,
}
