# -*- coding: utf-8 -*-
import base64
import functools
import json
import logging
import os

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request, Response
from odoo import registry as registry_get
from odoo.tools.misc import clean_context

from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.utils import ensure_db, _get_login_redirect_url
import string
import random
import requests

_logger = logging.getLogger(__name__)


# ----------------------------------------------------------
# helpers
# ----------------------------------------------------------
def fragment_to_query_string(func):
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        kw.pop('debug', False)
        if not kw:
            return Response("""<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>""")
        return func(self, *a, **kw)

    return wrapper


# ----------------------------------------------------------
# Controller
# ----------------------------------------------------------
class AuthenticateKeycloakLogin(Home):
    def get_keycloak_url(self, is_active):
        if is_active:
            return_url = request.httprequest.url_root + 'authenticate/keycloak'
            client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "")
            realm = os.environ.get("KEYCLOAK_REALM", "")
            auth_url = os.environ.get("KEYCLOAK_BASE_URL", "") + "/realms/" + realm + "/protocol/openid-connect/auth"
            state = self.get_state()
            params = dict(
                response_type='code',
                client_id=client_id,
                redirect_uri=return_url,
                scope='openid',
                state=json.dumps(state),
                # nonce=base64.urlsafe_b64encode(os.urandom(16)),
            )
            return "%s?%s" % (auth_url, werkzeug.urls.url_encode(params))
        else:
            return ""

    def get_state(self):
        redirect = request.params.get('redirect') or 'web'
        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        state = dict(
            d=request.session.db,
            r=werkzeug.urls.url_quote_plus(redirect),
            m=''.join(random.choices(string.ascii_uppercase + string.digits, k=40))
        )
        token = request.params.get('token')
        if token:
            state['t'] = token
        return state

    @http.route()
    def web_login(self, *args, **kw):
        auth_with_keycloak = request.env['ir.config_parameter'].sudo().get_param('authenticate_keycloak.is_active')
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
            return request.redirect(request.params.get('redirect'))

        response = super(AuthenticateKeycloakLogin, self).web_login(*args, **kw)
        if response.is_qweb:
            error = request.params.get('oauth_error')
            if error == '1':
                error = _("Sign up is not allowed on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _(
                    "You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
            else:
                error = None

            response.qcontext['keycloak_is_active'] = auth_with_keycloak
            response.qcontext['keycloak_url'] = self.get_keycloak_url(auth_with_keycloak)
            response.qcontext['keycloak_css_class'] = request.env['ir.config_parameter'].sudo().get_param(
                'authenticate_keycloak.css_class')
            response.qcontext['keycloak_button_label'] = request.env['ir.config_parameter'].sudo().get_param(
                'authenticate_keycloak.button_label')
            if error:
                response.qcontext['error'] = error

        return response


class AuthenticateKeycloakController(http.Controller):

    @http.route('/authenticate/keycloak', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        state = json.loads(kw['state'])

        # make sure request.session.db and state['d'] are the same,
        # update the session and retry the request otherwise
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()
        ensure_db(db=dbname)

        request.update_context(**clean_context(state.get('c', {})))
        try:
            code = kw.get('code')
            if not code:
                return request.redirect('/web/login')

            client_id = os.environ.get('KEYCLOAK_CLIENT_ID', '')
            client_secret = os.environ.get('KEYCLOAK_CLIENT_SECRET', '')
            base_url = os.environ.get('KEYCLOAK_BASE_URL', '')
            redirect_uri = request.httprequest.base_url
            realm = os.environ.get('KEYCLOAK_REALM', '')
            token_url = base_url + '/realms/' + realm + '/protocol/openid-connect/token'
            userinfo_url = base_url + '/realms/' + realm + '/protocol/openid-connect/userinfo'

            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': client_id,
                'client_secret': client_secret
            }
            token_resp = requests.post(token_url, data=token_data)
            if token_resp.status_code != 200:
                return request.redirect('/web/login?error=token')

            tokens = token_resp.json()
            access_token = tokens.get('access_token')

            # Fetch user info
            headers = {'Authorization': f'Bearer {access_token}'}
            userinfo_resp = requests.get(userinfo_url, headers=headers)
            if userinfo_resp.status_code != 200:
                return request.redirect('/web/login?error=userinfo')

            userinfo = userinfo_resp.json()
            email = userinfo.get('email')
            name = userinfo.get('name') or userinfo.get('preferred_username')

            if not email:
                return request.redirect('/web/login?error=noemail')

            # Find or create user
            user = request.env['res.users'].sudo().search([('login', '=', email)], limit=1)
            if not user:
                user = request.env['res.users'].sudo().create({
                    'name': name,
                    'login': email,
                    'email': email,
                    'groups_id': [(6, 0, [request.env.ref('base.group_user').id])]
                })

            action = state.get('a')
            menu = state.get('m')
            redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
            url = '/web'
            if redirect:
                url = redirect
            elif action:
                url = '/web#action=%s' % action
            elif menu:
                url = '/web#menu_id=%s' % menu

            # Manually set session (simulate login)
            request.session.uid = user.id
            return request.redirect('/web')

        except AttributeError:  # TODO juc master: useless since ensure_db()
            # auth_signup is not installed
            _logger.error("auth_signup not installed on database %s: oauth sign up cancelled.", dbname)
            url = "/web/login?oauth_error=1"
        except AccessDenied:
            # oauth credentials not valid, user could be on a temporary session
            _logger.info(
                'OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
            url = "/web/login?oauth_error=3"
        except Exception:
            # signup error
            _logger.exception("Exception during request handling")
            url = "/web/login?oauth_error=2"

        redirect = request.redirect(url, 303)
        redirect.autocorrect_location_header = False
        return redirect

#
#     @http.route('/auth_oauth/oea', type='http', auth='none')
#     def oea(self, **kw):
#         """login user via Odoo Account provider"""
#         dbname = kw.pop('db', None)
#         if not dbname:
#             dbname = request.db
#         if not dbname:
#             raise BadRequest()
#         if not http.db_filter([dbname]):
#             raise BadRequest()
#
#         registry = registry_get(dbname)
#         with registry.cursor() as cr:
#             try:
#                 env = api.Environment(cr, SUPERUSER_ID, {})
#                 provider = env.ref('auth_oauth.provider_openerp')
#             except ValueError:
#                 redirect = request.redirect(f'/web?db={dbname}', 303)
#                 redirect.autocorrect_location_header = False
#                 return redirect
#             assert provider._name == 'auth.oauth.provider'
#
#         state = {
#             'd': dbname,
#             'p': provider.id,
#             'c': {'no_user_creation': True},
#         }
#
#         kw['state'] = json.dumps(state)
#         return self.signin(**kw)
