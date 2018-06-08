# encoding: utf-8

import logging
import ckan.plugins as p
import ckan.plugins.toolkit as tk
from requests_oauthlib import OAuth2Session
from requests import HTTPError

log = logging.getLogger(__name__)


class OpenIDConnectPlugin(p.SingletonPlugin):
    """
    Plugin providing authentication using OpenID Connect.
    """
    p.implements(p.IAuthenticator)
    p.implements(p.IConfigurable)

    def configure(self, config):
        self.userinfo_endpoint = config.get('ckan.openidconnect.userinfo_endpoint')
        if not self.userinfo_endpoint:
            log.warning("Configuration value ckan.openidconnect.userinfo_endpoint has not been set")

        if tk.asbool(config.get('ckan.openidconnect.insecure_transport')):
            import os
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            log.warning("Allowing OAuth2 over insecure HTTP")

    def identify(self):
        if tk.c.user:
            return

        if not self.userinfo_endpoint:
            return

        auth_header = tk.request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = {'access_token': auth_header[len('Bearer '):]}
        else:
            log.error("Invalid authorization header; expecting bearer token")
            return

        oauth2session = OAuth2Session(token=token)
        response = oauth2session.get(self.userinfo_endpoint)
        try:
            response.raise_for_status()
            claims = response.json()
            openid_user = claims.get('sub')
            if not openid_user:
                raise ValueError("Missing OpenID user ID")

        except (HTTPError, ValueError) as e:
            log.error("Invalid response from authorization server: " + str(e))
            return

        try:
            tk.get_action('user_show')({}, {'id': openid_user})
            log.debug("Found user record for OpenID user %s", openid_user)

        except tk.ObjectNotFound:
            log.info("Automatically creating user record for OpenID user %s", openid_user)
            schema = {'id': [unicode], 'name': [unicode]}
            tk.get_action('user_create')({'schema': schema}, {'id': openid_user, 'name': openid_user})

        tk.c.user = openid_user
