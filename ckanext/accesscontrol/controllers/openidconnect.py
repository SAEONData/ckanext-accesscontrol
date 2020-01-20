# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckanext.accesscontrol.logic import openidconnect


class OpenIDConnectController(tk.BaseController):

    def login(self):
        """
        A user has clicked the "Login" link in the CKAN UI.
        """
        openidconnect.login()

    def register(self):
        """
        A user has clicked the "Register" link in the CKAN UI.
        """
        openidconnect.register()

    def callback(self):
        """
        Callback from the auth server after the user has logged in.
        """
        openidconnect.callback()

    def logout(self):
        """
        A logged in user has clicked the "Logout" link in the CKAN UI.
        """
        openidconnect.logout()

    def logged_out(self):
        """
        Callback from the auth server after the user has been logged out.
        """
        openidconnect.logged_out()
