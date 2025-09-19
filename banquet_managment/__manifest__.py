{
    "name" : "Banquet Management ",
    "version" : "18.0.1.2",
    "author" : "Pragmatic",
    "category" : "Generic Modules/Banquet Management",

    "description": """
    Module for Banquet/Resort/Property management. You can manage:
    * Configure Property
    * Banquet Configuration
    * Check In, Check out
    * Manage Folio
    * Payment

    Different reports are also provided, mainly for Banquet statistics.
    

    This module is upgraded by the following:
    Shawal Ahmad Mohmand
    Facebook: https://facebook.com/kkamaljan
    GitHub: https://github.com/criticalmiind
    Google: https://www.google.com/search?q=shawal+ahmad+mohmand
    Contact: +92 304 9758182
    Email: kamaljankamal4@gmail.com
""",
    "depends": ["base", 'hotel', 'crm', 'hotel_management'],
    "init_xml": [],
    "demo_xml": [
    ],
    "data": [
        'security/banquet_security.xml',
        'security/ir.model.access.csv',
        "views/banquet_managment_view.xml",
        'views/banquet_sequence_view.xml'

    ],
    "active": False,
    "installable": True,
    'license': 'OPL-1',
}
