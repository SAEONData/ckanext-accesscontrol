# encoding: utf-8

import pkg_resources

__version__ = pkg_resources.require('ckanext-openidconnect')[0].version


class OpenIDConnectError(Exception):
    pass
