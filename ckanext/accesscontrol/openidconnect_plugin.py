# encoding: utf-8

import ckan.plugins as p
from ckanext.accesscontrol.config import config
from ckanext.accesscontrol.logic import openidconnect


class OpenIDConnectPlugin(p.SingletonPlugin):

    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthenticator, inherit=True)

    def before_map(self, map):
        """
        Configure routes.
        """
        # load config here (instead of in IConfigurable.configure) because before_map is called before configure
        config.load_common_options()
        config.load_openidconnect_options()

        with map.submapper(controller='ckanext.accesscontrol.controllers.openidconnect:OpenIDConnectController') as m:
            m.connect('/user/register', action='register')
            m.connect('/user/login', action='login')
            m.connect('/user/_logout', action='logout')
            m.connect('/oidc/callback', action='callback')
            m.connect('/oidc/logged_out', action='logged_out')

        map.redirect('/user/edit/{user}', config.edit_url)

        return map

    def identify(self):
        """
        Identify the user who is making the call to CKAN.
        """
        openidconnect.identify()
