# encoding: utf-8

import os
import logging
from six.moves.urllib.parse import urljoin
from paste.deploy.converters import asbool

from ckan.common import config as ckan_config

log = logging.getLogger(__name__)

_config_defaults = {}


class AccessControlConfigError(Exception):
    pass


class AccessControlConfig(object):

    def _get_option(self, key):
        default = _config_defaults.get(key)
        value = ckan_config.get(key, default)
        if value:
            return unicode(value)
        self._missing += [key]

    def load_common_options(self):
        """
        Load the config options common to multiple plugins in this extension.
        """
        pass

    def load_openidconnect_options(self):
        """
        Load the config options specifically used by the openidconnect plugin.
        """
        if asbool(ckan_config.get('ckan.openidconnect.insecure_transport')):
            if not asbool(os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')):
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                log.warning("Allowing OAuth2 over insecure HTTP")

        self.no_verify_ssl_cert = asbool(ckan_config.get('ckan.openidconnect.no_verify_ssl_cert'))
        self.ckan_url = urljoin(ckan_config.get('ckan.site_url'), ckan_config.get('ckan.root_path'))
        self.redirect_url = urljoin(self.ckan_url, 'oidc/callback')
        self.postlogout_redirect_url = urljoin(self.ckan_url, 'oidc/logged_out')

        self._missing = []
        self.authorization_endpoint = self._get_option('ckan.openidconnect.authorization_endpoint')
        self.token_endpoint = self._get_option('ckan.openidconnect.token_endpoint')
        self.endsession_endpoint = self._get_option('ckan.openidconnect.endsession_endpoint')
        self.introspection_endpoint = self._get_option('ckan.openidconnect.introspection_endpoint')
        self.userinfo_endpoint = self._get_option('ckan.openidconnect.userinfo_endpoint')
        self.client_id = self._get_option('ckan.openidconnect.client_id')
        self.client_secret = self._get_option('ckan.openidconnect.client_secret')
        self.api_scope = self._get_option('ckan.openidconnect.api_scope')
        self.api_id = self._get_option('ckan.openidconnect.api_id')
        self.api_secret = self._get_option('ckan.openidconnect.api_secret')
        self.edit_url = self._get_option('ckan.openidconnect.edit_url')
        if self._missing:
            raise AccessControlConfigError("Missing configuration options(s): %s", ', '.join(self._missing))

        self.scopes = ['openid', self.api_scope]


config = AccessControlConfig()
