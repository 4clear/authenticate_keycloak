# -*- coding: utf-8 -*-
{
    'name': "Auth with Keycloak",
    'summary': "Auth with Keycloak",
    'description': """
Auth with Keycloak
    """,

    'author': "Achmad Rynaldi",
    'website': "https://www.yourcompany.com",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/15.0/odoo/addons/base/data/ir_module_category_data.xml
    # for the full list
    'category': 'Hidden/Tools',
    'version': '0.1',

    # any module necessary for this one to work correctly
    'depends': ['base', 'web', 'base_setup', 'auth_signup'],

    'data': [
        'views/res_config_settings_views.xml',
        'views/login_keycloak.xml',
    ],
    # only loaded in demonstration mode
    'demo': [
        # 'demo/demo.xml',
    ],
}

