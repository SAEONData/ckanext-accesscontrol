# encoding: utf-8

import logging
import os
from requests_oauthlib import OAuth2Session
from six.moves.urllib.parse import urljoin

import ckan.plugins.toolkit as tk
from ckan.common import _, config
from ckan.lib.redis import is_redis_available, connect_to_redis
from ckanext.openidconnect import OpenIDConnectError

log = logging.getLogger(__name__)


class OpenIDConnect(object):

    def __init__(self):

        def get_option(key):
            value = config.get(key)
            if value:
                return unicode(value)
            self._missing += [key]

        if tk.asbool(config.get('ckan.openidconnect.insecure_transport')):
            if not tk.asbool(os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')):
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                log.warning("Allowing OAuth2 over insecure HTTP")

        self.is_redis_available = is_redis_available()
        if not self.is_redis_available:
            log.warning("Redis is not available; OAuth2 session states will not be verifiable")

        self.ckan_url = urljoin(config.get('ckan.site_url'), config.get('ckan.root_path'))
        self.redirect_url = urljoin(self.ckan_url, 'openidconnect/callback')

        self._missing = []
        self.userinfo_endpoint = get_option('ckan.openidconnect.userinfo_endpoint')
        self.authorization_endpoint = get_option('ckan.openidconnect.authorization_endpoint')
        self.token_endpoint = get_option('ckan.openidconnect.token_endpoint')
        self.client_id = get_option('ckan.openidconnect.client_id')
        self.client_secret = get_option('ckan.openidconnect.client_secret')
        self.scopes = get_option('ckan.openidconnect.scopes')
        self.register_url = get_option('ckan.openidconnect.register_url')
        self.reset_url = get_option('ckan.openidconnect.reset_url')
        self.edit_url = get_option('ckan.openidconnect.edit_url')
        if self._missing:
            raise OpenIDConnectError("Missing configuration options(s): %s", ', '.join(self._missing))

    def login(self):
        log.debug("Login initiated")
        oauth2session = OAuth2Session(client_id=self.client_id, scope=self.scopes, redirect_uri=self.redirect_url)
        authorization_url, state = oauth2session.authorization_url(self.authorization_endpoint)
        self._save_state(state)

        tk.redirect_to(authorization_url)

    def callback(self):
        log.debug("Callback from auth server")
        try:
            error = tk.request.params.get('error')
            if error:
                error_description = tk.request.params.get('error_description', '')
                raise OpenIDConnectError(_("Authorization server returned an error: %s %s") % (error, error_description))

            auth_code = tk.request.params['code']
            state = tk.request.params['state']
            self._verify_state(state)

            oauth2session = OAuth2Session(client_id=self.client_id, redirect_uri=self.redirect_url)
            token = oauth2session.fetch_token(self.token_endpoint, client_secret=self.client_secret, code=auth_code)
            user_id, user_data = self._request_userinfo(token)
            self._persist_user(user_id, user_data)
            self._remember_login(user_id)
        except Exception, e:
            log.error(str(e))
            tk.h.flash_error(str(e))

        tk.redirect_to(self.ckan_url)

    def identify(self):
        if tk.c.user:
            return

        user_id = None
        user_data = None

        auth_header = tk.request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = {'access_token': auth_header[7:]}
            user_id, user_data = self._request_userinfo(token)

        if not user_id:
            environ = tk.request.environ
            user_id = environ.get('repoze.who.identity', {}).get('repoze.who.userid')

        if user_id:
            user_dict = self._persist_user(user_id, user_data)
            tk.c.user = user_dict['name']

    def _save_state(self, state):
        """
        Save a state string, used for verifying an OAuth2 login callback, to Redis,
        with an expiry time of 5 minutes.
        """
        if self.is_redis_available:
            redis = connect_to_redis()
            redis.setex(state, '', 300)

    def _verify_state(self, state):
        """
        Check that the state string provided with a callback matches one that was sent
        to the auth server.
        """
        if self.is_redis_available:
            redis = connect_to_redis()
            if state not in redis:
                raise OpenIDConnectError(_("Invalid authorization state"))

    def _request_userinfo(self, token):
        """
        Get user info from the auth server.
        :param token: token dict obtained from the auth server token endpoint
        :returns: tuple(user_id, user_data) where user_data is a dict of additional user values
        """
        oauth2session = OAuth2Session(token=token)
        response = oauth2session.get(self.userinfo_endpoint)
        response.raise_for_status()
        claims = response.json()
        user_id = claims.get('UserId')
        user_data = {key: claims.get(key) for key in ('name', 'email', 'role')}
        return user_id, user_data

    @staticmethod
    def _persist_user(user_id, user_data):
        """
        Create or update a user in the CKAN database, to correspond with the OpenID user info
        obtained from the authorization server. If user_data is not provided, simply return
        the user record if it exists.

        :param user_id: OpenID user id; becomes the CKAN user id
        :param user_data: dict of additional user info obtained from the auth server

        :returns: the CKAN user record
        :rtype: dictionary
        """
        user_data = user_data or {}
        context = {
            'ignore_auth': True,
            'keep_email': True,
            'schema': {
                'id': [unicode],
                'name': [unicode],
                'email': [unicode],
                'sysadmin': [],
            },
        }
        data_dict = {
            'id': user_id,
            'name': user_data.get('name'),
            'email': user_data.get('email'),
            'sysadmin': user_data.get('role', '').lower() == 'sysadmin',
        }
        try:
            user_dict = tk.get_action('user_show')(context, {'id': user_id})

            if user_data:
                update = False
                for key, value in data_dict.iteritems():
                    if user_dict.get(key) != value:
                        update = True
                        break
                if update:
                    user_dict = tk.get_action('user_update')(context, data_dict)
                    log.info("Updated user record for OpenID user %s", user_id)

        except tk.ObjectNotFound:
            if not user_data:
                raise
            user_dict = tk.get_action('user_create')(context, data_dict)
            log.info("Created user record for OpenID user %s", user_id)

        return user_dict

    @staticmethod
    def _remember_login(user_id):
        """
        Tell repoze.who about our user; this creates a user id cookie.
        """
        environ = tk.request.environ
        plugins = environ.get('repoze.who.plugins', {})
        rememberer = plugins['auth_tkt']
        identity = {'repoze.who.userid': user_id}
        headers = rememberer.remember(environ, identity)
        for header, value in headers:
            tk.response.headers.add(header, value)
