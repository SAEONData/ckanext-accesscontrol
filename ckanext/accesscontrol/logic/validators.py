# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckan.common import _
import ckanext.accesscontrol.model as extmodel


def role_name_validator(key, data, errors, context):

    role_name = data[key]
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
