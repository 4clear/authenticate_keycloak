from odoo import fields, models, api
import os



class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'


    auth_keycloak_button_label = fields.Char(string='Button Name',
                                             default='Login with Keycloak',
                                             config_parameter="authenticate_keycloak.button_label")
    auth_keycloak_is_active = fields.Boolean(string='Activate Keycloak Login',
                                             config_parameter="authenticate_keycloak.is_active")
    auth_keycloak_css_class = fields.Char(string='CSS class',
                                          default='fa fa-fw fa-sign-in text-primary',
                                          config_parameter="authenticate_keycloak.css_class")
    auth_keycloak_client_id = fields.Char(string='Client ID',
                                          readonly=True,
                                          compute='_get_client_id',
                                          store=True,
                                         default=lambda self: os.environ.get("KEYCLOAK_CLIENT_ID", ""))
    auth_keycloak_base_url = fields.Char(string='Base URL',
                                         readonly=True,
                                         compute='_get_base_url',
                                         store=True,
                                         default=lambda self: os.environ.get("KEYCLOAK_BASE_URL", ""))

    @api.depends('auth_keycloak_is_active')
    def _get_client_id(self):
        self.auth_keycloak_client_id = os.getenv('KEYCLOAK_CLIENT_ID', '')
    @api.depends('auth_keycloak_is_active')
    def _get_base_url(self):
        self.auth_keycloak_client_id = os.getenv('KEYCLOAK_BASE_URL', '')