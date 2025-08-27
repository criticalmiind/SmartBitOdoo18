
{
    "name": "POS – Armenian HDM Fiscal Integration",
    "version": "18.0.1.0.0",
    "summary": "Multi‑POS fiscalization with Armenian HDM (ՀԴՄ) registers",
    "description": "Integrates Odoo POS terminals with Armenian HDM fiscal registers. "
                   "Fiscalizes sales, returns, and cash in/out; stores fiscal data; adds receipt fields; "
                   "supports safe parallel operation per terminal.",
    "author": "Pandora Tech + ChatGPT",
    "maintainer": "Pandora Tech",
    "website": "https://smsvirtual.uk",
    "license": "LGPL-3",
    "category": "Point of Sale",
    "depends": ["point_of_sale", "base"],
    "external_dependencies": {"python": ["pycryptodome"]},
    "data": [
        "security/ir.model.access.csv",
        "views/res_config_settings_views.xml",
        "data/pos_assets.xml"
    ],
    "assets": {},  # assets are injected via data/pos_assets.xml
    "installable": True,
    "application": False
}
