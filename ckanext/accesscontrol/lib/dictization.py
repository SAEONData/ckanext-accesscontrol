# encoding: utf-8

import ckan.lib.dictization as d
import ckanext.accesscontrol.model as extmodel


def role_dict_save(role_dict, context):
    role = context.get('role')
    if role:
        role_dict['id'] = role.id
    return d.table_dict_save(role_dict, extmodel.Role, context)


def role_dictize(role, context):
    role_dict = d.table_dictize(role, context)
    role_dict['display_name'] = role_dict['title'] or role_dict['name']
    return role_dict


def role_permission_dict_save(role_permission_dict, context):
    return d.table_dict_save(role_permission_dict, extmodel.RolePermission, context)


def role_permission_dictize(role_permission, context):
    role_permission_dict = d.table_dictize(role_permission, context)
    return role_permission_dict


def user_role_dict_save(user_role_dict, context):
    return d.table_dict_save(user_role_dict, extmodel.UserRole, context)


def user_role_dictize(user_role, context):
    user_role_dict = d.table_dictize(user_role, context)
    return user_role_dict


def permission_dictize(permission, context):
    session = context['session']
    permission_dict = d.table_dictize(permission, context)

    if context.get('include_actions'):
        action_names = session.query(extmodel.PermissionAction.action_name) \
            .filter_by(permission_id=permission.id) \
            .all()
        permission_dict['actions'] = [action for (action,) in action_names]

    return permission_dict


def permission_list_dictize(permission_list, context):
    return [permission_dictize(permission, context) for permission in permission_list]
