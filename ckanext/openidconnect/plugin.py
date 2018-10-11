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

    def before_map(self, m):
        controller = 'ckanext.openidconnect.controller:OpenIDConnectController'
        m.connect('/user/login', action='login', controller=controller)
        m.connect('/openidconnect/callback', action='callback', controller=controller)
        m.redirect('/user/register', self.openidconnect.register_url)
        m.redirect('/user/reset', self.openidconnect.reset_url)
        m.redirect('/user/edit', self.openidconnect.edit_url)
        return m

    def identify(self):
        self.openidconnect.identify()
