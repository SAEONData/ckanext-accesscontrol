# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckan.common import _
import ckanext.accesscontrol.model as extmodel
from ckanext.accesscontrol.openidconnect_config import config


def role_name_validator(key, data, errors, context):

    role_name = data[key]
    if config.is_sysadmin_role(role_name):
        raise tk.Invalid(_("The name '%s' is reserved for the built-in system administrator role.") % role_name)

    session = context['session']
    role = context.get('role')

    query = session.query(extmodel.Role.name) \
        .filter(extmodel.Role.name == role_name) \
        .filter(extmodel.Role.state != 'deleted')

    id_ = role.id if role else data.get(key[:-1] + ('id',))
    if id_ and id_ is not tk.missing:
        query = query.filter(extmodel.Role.id != id_)
    result = query.first()
    if result:
        raise tk.Invalid('%s: %s' % (_('Duplicate name'), _('Role')))


def action_list_validator(key, data, errors, context):

    actions = data[key]
    for action in actions:
        try:
            tk.get_action(action)
        except:
            errors[key].append(_('The action %s does not exist') % action)


def permission_unique_validator(key, data, errors, context):

    content_type = data.get(key[:-1] + ('content_type',))
    operation = data.get(key[:-1] + ('operation',))

    permission = extmodel.Permission.lookup(content_type, operation)
    if permission:
        raise tk.Invalid(_("Unique constraint violation: %s") % '(content_type, operation)')
