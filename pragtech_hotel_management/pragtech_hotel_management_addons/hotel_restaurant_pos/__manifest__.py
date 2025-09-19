{
    "name": "Hotel Restaurant POS",
    "version": "17.0.1.1",
    "author": "Pragmatic TechSoft Pvt Ltd",
    'website': 'http://pragtech.co.in/',
    "category": "Generic Modules/Hotel Restaurant POS",
    "description": """
    Module for Hotel Restaurant and POS intigration. You can manage:
    * Table booking as well as room booking from pos
    * Generate and process Kitchen Order ticket,
    """,
    # "update_xml": ['views/templates.xml',
    #                'views/hotel_restaurant_pos_view.xml', ]
    "depends": ['point_of_sale', 'hotel_management', 'hotel_restaurant', 'hotel', "sale_enhancement"],
    "data": [
        'security/ir.model.access.csv',
        # 'views/templates.xml',
        'views/hotel_restaurant_pos_view.xml',
        'wizard/pos_credit_details.xml',
        # 'views/pos_credit_sales_report.xml',
        # 'report/pos_credit_sale_report.xml',
        # 'views/hotel_pos_workflow.xml',
    ],
    'assets': {
        'point_of_sale._assets_pos': [
            'hotel_restaurant_pos/static/src/css/jquery.multiselect.css',
            'hotel_restaurant_pos/static/src/css/switch.css',
            'hotel_restaurant_pos/static/src/css/pos.css',
            'hotel_restaurant_pos/static/src/js/models.js',
            'hotel_restaurant_pos/static/src/js/screens.js',
            'hotel_restaurant_pos/static/src/js/roomlistscreen.js',
            'hotel_restaurant_pos/static/src/xml/hotel_pos.xml'
        ],

    },
    'license': 'OPL-1',
    'installable': True,
    'application': True,
}
