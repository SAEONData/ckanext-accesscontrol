# encoding: utf-8

import os
import logging
from six.moves.urllib.parse import urljoin
from paste.deploy.converters import asbool

from ckan.common import _, config as ckan_config
from ckan.lib.redis import is_redis_available

log = logging.getLogger(__name__)

_config_defaults = {
    'ckan.openidconnect.userid_field': 'sub',
    'ckan.openidconnect.username_field': 'name',
    'ckan.openidconnect.email_field': 'email',
    'ckan.openidconnect.rolename_field': 'role',
    'ckan.openidconnect.sysadmin_role': 'sysadmin',
}


class OpenIDConnectConfigError(Exception):
    pass


class OpenIDConnectConfig(object):

    def __init__(self):

        def get_option(key):
            default = _config_defaults.get(key)
            value = ckan_config.get(key, default)
            if value:
                return unicode(value)
            self._missing += [key]

        if not is_redis_available():
            raise OpenIDConnectConfigError("This plugin requires Redis")

        if asbool(ckan_config.get('ckan.openidconnect.insecure_transport')):
            if not asbool(os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')):
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                log.warning("Allowing OAuth2 over insecure HTTP")

        self.ckan_url = urljoin(ckan_config.get('ckan.site_url'), ckan_config.get('ckan.root_path'))
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
        self.userid_field = get_option('ckan.openidconnect.userid_field')
        self.username_field = get_option('ckan.openidconnect.username_field')
        self.email_field = get_option('ckan.openidconnect.email_field')
        self.rolename_field = get_option('ckan.openidconnect.rolename_field')
        self.sysadmin_role = get_option('ckan.openidconnect.sysadmin_role')
        if self._missing:
            raise OpenIDConnectConfigError("Missing configuration options(s): %s", ', '.join(self._missing))

        self.scopes = ['openid', self.api_scope]
        self.authorized_clients = self.authorized_clients.split()

    def is_sysadmin_role(self, role):
        """
        Test whether the given role name represents the sysadmin role.
        """
        return role.lower() == self.sysadmin_role.lower()


# todo: we should not try to read the openidconnect config if the openidconnect plugin is not enabled
config = OpenIDConnectConfig()
