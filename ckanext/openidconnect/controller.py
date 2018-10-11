# encoding: utf-8

import ckan.lib.base as base
from ckanext.openidconnect.openidconnect import OpenIDConnect


class OpenIDConnectController(base.BaseController):

    def __init__(self):
        self.openidconnect = OpenIDConnect()

    def login(self):
        self.openidconnect.login()

    def callback(self):
        self.openidconnect.callback()
