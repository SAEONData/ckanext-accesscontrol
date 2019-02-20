# encoding: utf-8

import ckan.lib.dictization as d
from ckanext.accesscontrol.model.role import Role
from ckanext.accesscontrol.model.role_permission import RolePermission
from ckanext.accesscontrol.model.user_role import UserRole


def role_dict_save(role_dict, context):
    role = context.get('role')
    if role:
        role_dict['id'] = role.id
    return d.table_dict_save(role_dict, Role, context)


def role_dictize(role, context):
    role_dict = d.table_dictize(role, context)
    role_dict['display_name'] = role_dict['title'] or role_dict['name']
    return role_dict


def role_permission_dict_save(role_permission_dict, context):
    return d.table_dict_save(role_permission_dict, RolePermission, context)


def user_role_dict_save(user_role_dict, context):
    return d.table_dict_save(user_role_dict, UserRole, context)
