# encoding: utf-8

import os
import logging
from six.moves.urllib.parse import urljoin
from paste.deploy.converters import asbool

from ckan.common import _, config as ckan_config
from ckan.lib.redis import is_redis_available
from ckanext.accesscontrol import AccessControlError

log = logging.getLogger(__name__)

_config_defaults = {
    'ckan.accesscontrol.userid_field': 'sub',
    'ckan.accesscontrol.username_field': 'name',
    'ckan.accesscontrol.email_field': 'email',
    'ckan.accesscontrol.rolename_field': 'role',
    'ckan.accesscontrol.sysadmin_role': 'sysadmin',
}

_actions_with_automatic_permission = (
    'site_read',
    'user_create',
)


def is_action_permission_automatic(action_name):
    return action_name in _actions_with_automatic_permission


class AccessControlConfig(object):

    def __init__(self):

        def get_option(key):
            default = _config_defaults.get(key)
            value = ckan_config.get(key, default)
            if value:
                return unicode(value)
            self._missing += [key]

        if not is_redis_available():
            raise AccessControlError("This extension requires Redis")

        if asbool(ckan_config.get('ckan.accesscontrol.insecure_transport')):
            if not asbool(os.environ.get('OAUTHLIB_INSECURE_TRANSPORT')):
                os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                log.warning("Allowing OAuth2 over insecure HTTP")

        self.ckan_url = urljoin(ckan_config.get('ckan.site_url'), ckan_config.get('ckan.root_path'))
        self.redirect_url = urljoin(self.ckan_url, 'oidc/callback')
        self.postlogout_redirect_url = urljoin(self.ckan_url, 'oidc/logged_out')

        self._missing = []
        self.authorization_endpoint = get_option('ckan.accesscontrol.authorization_endpoint')
        self.token_endpoint = get_option('ckan.accesscontrol.token_endpoint')
        self.endsession_endpoint = get_option('ckan.accesscontrol.endsession_endpoint')
        self.introspection_endpoint = get_option('ckan.accesscontrol.introspection_endpoint')
        self.userinfo_endpoint = get_option('ckan.accesscontrol.userinfo_endpoint')
        self.client_id = get_option('ckan.accesscontrol.client_id')
        self.client_secret = get_option('ckan.accesscontrol.client_secret')
        self.api_scope = get_option('ckan.accesscontrol.api_scope')
        self.api_id = get_option('ckan.accesscontrol.api_id')
        self.api_secret = get_option('ckan.accesscontrol.api_secret')
        self.authorized_clients = get_option('ckan.accesscontrol.authorized_clients')
        self.register_url = get_option('ckan.accesscontrol.register_url')
        self.reset_url = get_option('ckan.accesscontrol.reset_url')
        self.edit_url = get_option('ckan.accesscontrol.edit_url')
        self.userid_field = get_option('ckan.accesscontrol.userid_field')
        self.username_field = get_option('ckan.accesscontrol.username_field')
        self.email_field = get_option('ckan.accesscontrol.email_field')
        self.rolename_field = get_option('ckan.accesscontrol.rolename_field')
        self.sysadmin_role = get_option('ckan.accesscontrol.sysadmin_role')
        if self._missing:
            raise AccessControlError("Missing configuration options(s): %s", ', '.join(self._missing))

        self.scopes = ['openid', self.api_scope]
        self.authorized_clients = self.authorized_clients.split()

    def is_sysadmin_role(self, role):
        """
        Test whether the given role name represents the sysadmin role.
        """
        return role.lower() == self.sysadmin_role.lower()


config = AccessControlConfig()
