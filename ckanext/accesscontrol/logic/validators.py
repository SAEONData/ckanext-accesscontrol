# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckanext.accesscontrol.model.role import Role
from ckanext.accesscontrol.openidconnect_config import config


def role_name_validator(key, data, errors, context):

    role_name = data[key]
    if config.is_sysadmin_role(role_name):
        raise tk.Invalid(_("The name '%s' is reserved for the built-in system administrator role.") % role_name)

    session = context['session']
    role = context.get('role')

    query = session.query(Role.name) \
        .filter(Role.name == role_name) \
        .filter(Role.state != 'deleted')

    id_ = role.id if role else data.get(key[:-1] + ('id',))
    if id_ and id_ is not tk.missing:
        query = query.filter(Role.id != id_)
    result = query.first()
    if result:
        raise tk.Invalid('%s: %s' % (_('Duplicate name'), _('Role')))
