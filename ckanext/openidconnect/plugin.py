# encoding: utf-8

import ckan.plugins as p
from ckanext.openidconnect.openidconnect import OpenIDConnect


class OpenIDConnectPlugin(p.SingletonPlugin):
    """
    Plugin providing authentication, authorization and user management via an
    OpenIDConnect / OAuth2 server.
    """
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthenticator, inherit=True)

    def __init__(self, **kwargs):
        self.openidconnect = OpenIDConnect()

    def before_map(self, map):
        with map.submapper(controller='ckanext.openidconnect.controller:OpenIDConnectController') as m:
            m.connect('/user/login', action='login')
            m.connect('/user/_logout', action='logout')
            m.connect('/oidc/callback', action='callback')
            m.connect('/oidc/logged_out', action='logged_out')

        map.redirect('/user/register', self.openidconnect.register_url)
        map.redirect('/user/reset', self.openidconnect.reset_url)
        map.redirect('/user/edit/{user}', self.openidconnect.edit_url)

        return map

    def identify(self):
        self.openidconnect.identify()
