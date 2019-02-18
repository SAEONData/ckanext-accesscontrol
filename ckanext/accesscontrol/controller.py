# encoding: utf-8

import ckan.lib.base as base
from ckanext.accesscontrol import logic


class AccessControlController(base.BaseController):

    def login(self):
        logic.login()

    def callback(self):
        logic.callback()

    def logout(self):
        logic.logout()

    def logged_out(self):
        logic.logged_out()
