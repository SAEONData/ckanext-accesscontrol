# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckanext.accesscontrol.logic import openidconnect


class OpenIDConnectController(tk.BaseController):

    def login(self):
        openidconnect.login()

    def callback(self):
        openidconnect.callback()

    def logout(self):
        openidconnect.logout()

    def logged_out(self):
        openidconnect.logged_out()
