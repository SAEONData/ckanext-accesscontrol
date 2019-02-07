# encoding: utf-8

import logging
import os
import json
import requests
from requests_oauthlib import OAuth2Session
from six.moves.urllib.parse import urljoin
from oauthlib.oauth2 import OAuth2Error
from requests import RequestException

import ckan.plugins.toolkit as tk
from ckan.common import _, config
from ckan.lib.redis import is_redis_available, connect_to_redis
from ckanext.openidconnect import OpenIDConnectError

log = logging.getLogger(__name__)
anyAuthException = (OpenIDConnectError, OAuth2Error, RequestException)


class OpenIDConnect(object):

    def __init__(self):

        def get_option(key, default=None):
            value = config.get(key, default)
            if value:
                return unicode(value)
            self._missing += [key]

        if not is_redis_available():
            raise OpenIDConnectError("This extension requires Redis")

        if tk.asbool(config.get('ckan.openidconnect.insecure_transport')):
            if not tk.asbool(os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')):
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                log.warning("Allowing OAuth2 over insecure HTTP")

        self.ckan_url = urljoin(config.get('ckan.site_url'), config.get('ckan.root_path'))
        self.redirect_url = urljoin(self.ckan_url, 'oidc/callback')
        self.postlogout_redirect_url = urljoin(self.ckan_url, 'oidc/logged_out')

        self._missing = []
        self.authorization_endpoint = get_option('ckan.openidconnect.authorization_endpoint')
        self.token_endpoint = get_option('ckan.openidconnect.token_endpoint')
        self.endsession_endpoint = get_option('ckan.openidconnect.endsession_endpoint')
        self.introspection_endpoint = get_option('ckan.openidconnect.introspection_endpoint')
        self.userinfo_endpoint = get_option('ckan.openidconnect.userinfo_endpoint')
        self.client_id = get_option('ckan.openidconnect.client_id')
        self.client_secret = get_option('ckan.openidconnect.client_secret')
        self.api_scope = get_option('ckan.openidconnect.api_scope')
        self.api_id = get_option('ckan.openidconnect.api_id')
        self.api_secret = get_option('ckan.openidconnect.api_secret')
        self.authorized_clients = get_option('ckan.openidconnect.authorized_clients')
        self.register_url = get_option('ckan.openidconnect.register_url')
        self.reset_url = get_option('ckan.openidconnect.reset_url')
        self.edit_url = get_option('ckan.openidconnect.edit_url')
        self.userid_field = get_option('ckan.openidconnect.userid_field', 'sub')
        self.username_field = get_option('ckan.openidconnect.username_field', 'name')
        self.email_field = get_option('ckan.openidconnect.email_field', 'email')
        self.rolename_field = get_option('ckan.openidconnect.rolename_field', 'role')
        self.sysadmin_role = get_option('ckan.openidconnect.sysadmin_role', 'sysadmin')
        if self._missing:
            raise OpenIDConnectError("Missing configuration options(s): %s", ', '.join(self._missing))

        self.scopes = ['openid', self.api_scope]
        self.authorized_clients = self.authorized_clients.split()

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
            self._validate_token(token)
            user_id, user_data = self._request_userinfo(token)
            self._save_token(user_id, token)
            self._persist_user(user_id, user_data)
            self._remember_login(user_id)

        except anyAuthException, e:
            log.error(str(e))
            tk.h.flash_error(str(e))

        tk.redirect_to(self.ckan_url)

    def identify(self):
        if getattr(tk.c, 'user', None):
            return

        log.debug("Identifying user")
        user_id = None
        user_data = None

        # API calls should arrive with an access token in the auth header
        auth_header = tk.request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = {'access_token': auth_header[7:]}
            try:
                self._validate_token(token)
                user_id, user_data = self._request_userinfo(token)
            except anyAuthException, e:
                log.error(str(e))
                return

        # if not an API call, we're dealing with a user logged in via the CKAN UI
        if not user_id:
            environ = tk.request.environ
            user_id = environ.get('repoze.who.identity', {}).get('repoze.who.userid')

        if user_id:
            user_dict = self._persist_user(user_id, user_data)
            tk.c.user = user_dict['name']

    def logout(self):
        log.debug("Logout initiated")
        self._forget_login()
        user_id = tk.c.userobj.id
        token = self._load_token(user_id)
        id_token = token.get('id_token') if token else ''
        logout_url = self.endsession_endpoint + \
                     '?post_logout_redirect_uri=' + self.postlogout_redirect_url + \
                     '&id_token_hint=' + id_token
        tk.redirect_to(logout_url)

    def logged_out(self):
        log.debug("Post-logout callback from auth server")
        self._forget_login()
        tk.redirect_to(self.ckan_url)

    @staticmethod
    def _save_state(state):
        """
        Save a state string, used for verifying an OAuth2 login callback, to Redis,
        with an expiry time of 5 minutes.
        """
        redis = connect_to_redis()
        key = 'oidc_state:' + state
        redis.setex(key, '', 300)

    @staticmethod
    def _verify_state(state):
        """
        Check that the state string provided with a callback matches one that was sent
        to the auth server.
        """
        redis = connect_to_redis()
        key = 'oidc_state:' + state
        if key not in redis:
            raise OpenIDConnectError(_("Invalid authorization state"))

    @staticmethod
    def _save_token(user_id, token):
        """
        Save a user's auth token to Redis, with the expiry time specified within the token.
        """
        expiry_time = token.get('expires_in', 300)
        redis = connect_to_redis()
        key = 'oidc_token:' + user_id
        redis.setex(key, json.dumps(token), expiry_time)

    @staticmethod
    def _load_token(user_id):
        """
        Retrieve a user's auth token from Redis.
        """
        redis = connect_to_redis()
        key = 'oidc_token:' + user_id
        token = redis.get(key) or '{}'
        token = json.loads(token)
        return token

    def _validate_token(self, token):
        """
        Get detailed info about the access token from the auth server, and check that it is
        valid for our CKAN instance.
        :param token: token dictionary
        """
        access_token = token.get('access_token') if token else ''
        response = requests.post(self.introspection_endpoint, data={'token': access_token}, auth=(self.api_id, self.api_secret))
        response.raise_for_status()
        result = response.json()
        scopes = result.get('scope', '').split()
        client_id = result.get('client_id')
        valid = result.get('active') and \
                self.api_scope in scopes and \
                client_id in self.authorized_clients
        if not valid:
            raise OpenIDConnectError(_("Invalid access token"))

    def _request_userinfo(self, token):
        """
        Get user info from the auth server.
        :param token: token dictionary
        :returns: tuple(user_id, user_data) where user_data is a dict of additional user values
        """
        oauth2session = OAuth2Session(token=token)
        response = oauth2session.get(self.userinfo_endpoint)
        response.raise_for_status()
        claims = response.json()
        user_id = claims.get(self.userid_field)
        user_data = {key: claims.get(key, '') for key in (self.username_field, self.email_field)}
        roles = claims.get(self.rolename_field) or []
        if isinstance(roles, basestring):
            roles = [roles]
        user_data[self.rolename_field] = roles
        return user_id, user_data

    def _persist_user(self, user_id, user_data):
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
        roles = user_data.get(self.rolename_field, [])
        is_sysadmin = any((True for role in roles if role.lower() == self.sysadmin_role.lower()))

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
            'name': user_data.get(self.username_field),
            'email': user_data.get(self.email_field),
            'sysadmin': is_sysadmin,
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
                    log.info("Updated user record for OpenID user %s (%s)", user_id, user_dict['name'])

        except tk.ObjectNotFound:
            if not user_data:
                raise
            user_dict = tk.get_action('user_create')(context, data_dict)
            log.info("Created user record for OpenID user %s (%s)", user_id, user_dict['name'])

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

    @staticmethod
    def _forget_login():
        """
        Tell repoze.who that we've logged out; this deletes the user id cookie.
        """
        environ = tk.request.environ
        plugins = environ.get('repoze.who.plugins', {})
        rememberer = plugins['auth_tkt']
        headers = rememberer.forget(environ, None)
        for header, value in headers:
            tk.response.headers.add(header, value)
