{
    "name": "Hotel Transport Management",
    "version": "18.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    'website': 'http://pragtech.co.in/',
    "category": "Generic Modules/Hotel Transport",
    "description": """
    Module for Hotel/Transport management. You can manage:
    * Task Creation For Transport
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["base", "hotel_management", 'banquet_managment', 'project'],
    "init_xml": [],
    "demo_xml": [],
    "data": [
        'security/transport_security.xml',
        "security/ir.model.access.csv",
        "views/hotel_transport_management_view.xml",
        "hotel_transport_data.xml",
    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
