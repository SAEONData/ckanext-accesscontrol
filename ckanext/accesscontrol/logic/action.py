# encoding: utf-8

import logging
from paste.deploy.converters import asbool

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckanext.accesscontrol.logic import schema
from ckanext.accesscontrol.lib import dictization
import ckanext.accesscontrol.model as extmodel
from ckanext.accesscontrol.logic import is_action_allowed_by_default

log = logging.getLogger(__name__)


@tk.side_effect_free
def user_privilege_check(context, data_dict):
    """
    Check whether a user has the privilege (via user roles and role permissions)
    to perform an action.

    :param user_id: the id or name of the user
    :type user_id: string
    :param action: the name of the action API function
    :type action: string

    :returns: dict{'success': T/F, 'msg': str}
    """
    result = {}
    try:
        model = context['model']
        session = context['session']

        user_id, action = tk.get_or_bust(data_dict, ['user_id', 'action'])

        if is_action_allowed_by_default(action):
            result = {
                'success': True,
                'msg': _('The action %s is allowed by default') % action
            }
            return result

        try:
            tk.get_action(action)
        except:
            raise tk.ValidationError({'action': [_('The action %s does not exist') % action]})

        user = model.User.get(user_id)
        if user is not None and user.state == 'active':
            user_id = user.id
        else:
            result = {
                'success': False,
                'msg': _('Unknown user')
            }
            return result

        if user.sysadmin:
            result = {
                'success': True,
                'msg': _('User is a sysadmin')
            }
            return result

        has_privilege = session.query(extmodel.UserRole).join(extmodel.Role).join(extmodel.RolePermission).join(extmodel.Permission).join(extmodel.PermissionAction) \
            .filter(extmodel.UserRole.user_id == user_id) \
            .filter(extmodel.UserRole.state == 'active') \
            .filter(extmodel.Role.state == 'active') \
            .filter(extmodel.RolePermission.state == 'active') \
            .filter(extmodel.Permission.state == 'active') \
            .filter(extmodel.PermissionAction.action_name == action) \
            .filter(extmodel.PermissionAction.state == 'active') \
            .count() > 0
        result = {
            'success': has_privilege,
            'msg': _('User is permitted to perform the action') if has_privilege else _('User is not permitted to perform the action')
        }
        return result

    except Exception, e:
        result = {'error': e.error_dict if hasattr(e, 'error_dict') else str(e)}
        raise
    finally:
        logresult = data_dict.copy()
        logresult.update(result)
        log.debug("user_privilege_check: %r", logresult)


def role_create(context, data_dict):
    """
    Create a new role.

    You must be a sysadmin to create roles.

    :param name: the name of the role; standard naming rules apply
    :type name: string
    :param title: the title of the role (optional)
    :type title: string
    :param description: a description of the role (optional)
    :type description: string

    :returns: the newly created role (unless 'return_id_only' is set to True
              in the context, in which case just the role id will be returned)
    :rtype: dictionary
    """
    log.info("Creating role: %r", data_dict)
    tk.check_access('role_create', context, data_dict)

    model = context['model']
    user = context['user']
    session = context['session']
    defer_commit = context.get('defer_commit', False)
    return_id_only = context.get('return_id_only', False)

    data, errors = tk.navl_validate(data_dict, schema.role_create_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    role = dictization.role_dict_save(data, context)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Create role %s') % role.id

    if not defer_commit:
        model.repo.commit()

    output = role.id if return_id_only \
        else tk.get_action('role_show')(context, {'id': role.id})
    return output


def role_update(context, data_dict):
    """
    Update a role.

    You must be a sysadmin to update roles.

    It is recommended to call
    :py:func:`ckan.logic.action.get.role_show`, make the desired changes to
    the result, and then call ``role_update()`` with it.

    For further parameters see
    :py:func:`~ckanext.accesscontrol.logic.action.role_create`.

    :param id: the id or name of the role to update
    :type id: string

    :returns: the updated role (unless 'return_id_only' is set to True
              in the context, in which case just the role id will be returned)
    :rtype: dictionary
    """
    log.info("Updating role: %r", data_dict)

    model = context['model']
    user = context['user']
    session = context['session']
    defer_commit = context.get('defer_commit', False)
    return_id_only = context.get('return_id_only', False)

    role_id = tk.get_or_bust(data_dict, 'id')
    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    tk.check_access('role_update', context, data_dict)

    data_dict.update({
        'id': role_id,
    })
    context.update({
        'role': role,
        'allow_partial_update': True,
    })

    data, errors = tk.navl_validate(data_dict, schema.role_update_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    role = dictization.role_dict_save(data, context)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Update role %s') % role_id

    if not defer_commit:
        model.repo.commit()

    output = role_id if return_id_only \
        else tk.get_action('role_show')(context, {'id': role_id})
    return output


def role_delete(context, data_dict):
    """
    Delete a role.

    You must be a sysadmin to delete roles.

    :param id: the id of the role to delete
    :type id: string
    """
    log.info("Deleting role: %r", data_dict)

    model = context['model']
    user = context['user']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    role_id = tk.get_or_bust(data_dict, 'id')
    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    tk.check_access('role_delete', context, data_dict)

    rev = model.repo.new_revision()
    rev.author = user
    rev.message = _(u'REST API: Delete Role %s') % role_id

    role.delete()
    if not defer_commit:
        model.repo.commit()


@tk.side_effect_free
def role_show(context, data_dict):
    """
    Return a role definition.

    You must be a sysadmin to view roles.

    :param id: the id of the role
    :type id: string

    :rtype: dictionary
    """
    log.debug("Retrieving role: %r", data_dict)

    role_id = tk.get_or_bust(data_dict, 'id')
    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    tk.check_access('role_show', context, data_dict)

    context['role'] = role
    role_dict = dictization.role_dictize(role, context)

    result_dict, errors = tk.navl_validate(role_dict, schema.role_show_schema(), context)
    return result_dict


@tk.side_effect_free
def role_list(context, data_dict):
    """
    Return a list of names of the site's roles.

    You must be a sysadmin to list roles.

    :param all_fields: return dictionaries instead of just ids (optional, default: ``False``)
    :type all_fields: boolean

    :rtype: list of strings
    """
    log.debug("Retrieving role list: %r", data_dict)
    tk.check_access('role_list', context, data_dict)

    session = context['session']
    all_fields = asbool(data_dict.get('all_fields'))

    roles = session.query(extmodel.Role.id, extmodel.Role.name) \
        .filter_by(state='active') \
        .all()
    result = []
    for (id_, name) in roles:
        if all_fields:
            data_dict['id'] = id_
            result += [tk.get_action('role_show')(context, data_dict)]
        else:
            result += [name]

    return result


def role_permission_grant(context, data_dict):
    """
    Grant a permission to a role.

    You must be a sysadmin to grant permissions.

    :param role_id: the id or name of the role
    :type role_id: string
    :param permission_id: the id of the permission
    :type permission_id: string

    :returns: the newly created role permission
    :rtype: dictionary
    """
    log.info("Granting permission to role: %r", data_dict)
    tk.check_access('role_permission_grant', context, data_dict)

    model = context['model']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    role_id, permission_id = tk.get_or_bust(data_dict, ['role_id', 'permission_id'])
    role = extmodel.Role.get(role_id)
    if role is not None and role.state == 'active':
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    permission = extmodel.Permission.get(permission_id)
    if permission is None or permission.state != 'active':
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    role_permission = extmodel.RolePermission.lookup(role_id, permission_id)
    if role_permission and role_permission.state == 'active':
        raise tk.ValidationError(_('The specified permission has already been granted to the role'))

    data_dict['role_id'] = role_id
    data_dict['state'] = 'active'
    role_permission = dictization.role_permission_dict_save(data_dict, context)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Grant permission to role %s: %s on %s') % (role.name, permission.operation, permission.content_type)

    if not defer_commit:
        model.repo.commit()

    return dictization.role_permission_dictize(role_permission, context)


def role_permission_revoke(context, data_dict):
    """
    Revoke a permission from a role.

    You must be a sysadmin to revoke permissions.

    :param role_id: the id or name of the role
    :type role_id: string
    :param permission_id: the id of the permission
    :type permission_id: string
    """
    log.info("Revoking permission from role: %r", data_dict)
    tk.check_access('role_permission_revoke', context, data_dict)

    model = context['model']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    role_id, permission_id = tk.get_or_bust(data_dict, ['role_id', 'permission_id'])
    role = extmodel.Role.get(role_id)
    if role is not None and role.state == 'active':
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    permission = extmodel.Permission.get(permission_id)
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    role_permission = extmodel.RolePermission.lookup(role_id, permission_id)
    if not role_permission or role_permission.state != 'active':
        raise tk.ValidationError(_('The role does not have the specified permission'))

    role_permission.delete()

    rev = model.repo.new_revision()
    rev.author = user
    rev.message = _(u'REST API: Revoke permission from role %s: %s on %s') % (role.name, permission.operation, permission.content_type)

    if not defer_commit:
        model.repo.commit()


@tk.side_effect_free
def role_permission_list(context, data_dict):
    """
    Return a list of permissions for a role.

    You must be a sysadmin to list role permissions.

    :param role_id: the id or name of the role
    :type role_id: string

    :returns: list of dicts
    """
    log.debug("Retrieving role permission list: %r", data_dict)
    tk.check_access('role_permission_list', context, data_dict)

    session = context['session']

    role_id = tk.get_or_bust(data_dict, 'role_id')
    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    permissions = session.query(extmodel.Permission) \
        .join(extmodel.RolePermission) \
        .filter(extmodel.RolePermission.role_id == role_id) \
        .filter(extmodel.RolePermission.state == 'active') \
        .filter(extmodel.Permission.state == 'active') \
        .all()
    return dictization.permission_list_dictize(permissions, context)


def user_role_assign(context, data_dict):
    """
    Assign a role to a user.

    You must be a sysadmin to assign roles.

    :param user_id: the id or name of the user
    :type user_id: string
    :param role_id: the id or name of the role
    :type role_id: string

    :returns: the newly created user role
    :rtype: dictionary
    """
    log.info("Assigning role to user: %r", data_dict)
    tk.check_access('user_role_assign', context, data_dict)

    model = context['model']
    author = context['user']
    defer_commit = context.get('defer_commit', False)

    user_id, role_id = tk.get_or_bust(data_dict, ['user_id', 'role_id'])
    user = model.User.get(user_id)
    if user is not None and user.state == 'active':
        user_id = user.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('User')))

    role = extmodel.Role.get(role_id)
    if role is not None and role.state == 'active':
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    user_role = extmodel.UserRole.lookup(user_id, role_id)
    if user_role and user_role.state == 'active':
        raise tk.ValidationError(_('The role has already been assigned to the user'))

    data_dict['user_id'] = user_id
    data_dict['role_id'] = role_id
    data_dict['state'] = 'active'
    user_role = dictization.user_role_dict_save(data_dict, context)

    rev = model.repo.new_revision()
    rev.author = author
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Assign role %s to user %s') % (role.name, user.name)

    if not defer_commit:
        model.repo.commit()

    return dictization.user_role_dictize(user_role, context)


def user_role_unassign(context, data_dict):
    """
    Unassign a role from a user.

    You must be a sysadmin to unassign roles.

    :param user_id: the id or name of the user
    :type user_id: string
    :param role_id: the id or name of the role
    :type role_id: string
    """
    log.info("Unassigning role from user: %r", data_dict)
    tk.check_access('user_role_unassign', context, data_dict)

    model = context['model']
    author = context['user']
    defer_commit = context.get('defer_commit', False)

    user_id, role_id = tk.get_or_bust(data_dict, ['user_id', 'role_id'])
    user = model.User.get(user_id)
    if user is not None and user.state == 'active':
        user_id = user.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('User')))

    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    user_role = extmodel.UserRole.lookup(user_id, role_id)
    if not user_role or user_role.state != 'active':
        raise tk.ValidationError(_('The user does not have the specified role'))

    user_role.delete()

    rev = model.repo.new_revision()
    rev.author = author
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Unassign role %s from user %s') % (role.name, user.name)

    if not defer_commit:
        model.repo.commit()


@tk.side_effect_free
def user_role_list(context, data_dict):
    """
    Return a list of roles that are assigned to a user.

    You must be a sysadmin to list user roles.

    :param user_id: the id or name of the user
    :type user_id: string
    :param all_fields: return dictionaries instead of just names (optional, default: ``False``)
    :type all_fields: boolean

    :returns: list of role names
    """
    log.debug("Retrieving user role list: %r", data_dict)
    tk.check_access('user_role_list', context, data_dict)

    model = context['model']
    session = context['session']
    all_fields = asbool(data_dict.get('all_fields'))

    user_id = tk.get_or_bust(data_dict, 'user_id')
    user = model.User.get(user_id)
    if user is not None:
        user_id = user.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('User')))

    roles = session.query(extmodel.Role.id, extmodel.Role.name) \
        .join(extmodel.UserRole) \
        .filter(extmodel.Role.state == 'active') \
        .filter(extmodel.UserRole.user_id == user_id) \
        .filter(extmodel.UserRole.state == 'active') \
        .all()
    result = []
    for (id_, name) in roles:
        if all_fields:
            data_dict['id'] = id_
            result += [tk.get_action('role_show')(context, data_dict)]
        else:
            result += [name]

    return result


@tk.side_effect_free
def role_user_list(context, data_dict):
    """
    Return a list of users that are assigned a given role.

    You must be a sysadmin to list role users.

    :param role_id: the id or name of the role
    :type role_id: string
    :param all_fields: return dictionaries instead of just names (optional, default: ``False``)
    :type all_fields: boolean

    :returns: list of user names
    """
    log.debug("Retrieving role user list: %r", data_dict)
    tk.check_access('role_user_list', context, data_dict)

    model = context['model']
    session = context['session']
    all_fields = asbool(data_dict.get('all_fields'))

    role_id = tk.get_or_bust(data_dict, 'role_id')
    role = extmodel.Role.get(role_id)
    if role is not None:
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    users = session.query(model.User.id, model.User.name) \
        .join(extmodel.UserRole) \
        .filter(model.User.state == 'active') \
        .filter(extmodel.UserRole.role_id == role_id) \
        .filter(extmodel.UserRole.state == 'active') \
        .all()
    result = []
    for (id_, name) in users:
        if all_fields:
            data_dict['id'] = id_
            result += [tk.get_action('user_show')(context, data_dict)]
        else:
            result += [name]

    return result


@tk.side_effect_free
def permission_list(context, data_dict):
    """
    Return a list of the site's permissions.

    You must be a sysadmin to list permissions.

    :param include_actions: include a list of associated action names in the result
        dictionaries (optional, default: ``False``)
    :type include_actions: boolean

    :rtype: list of dicts
    """
    log.debug("Retrieving permission list: %r", data_dict)
    tk.check_access('permission_list', context, data_dict)

    session = context['session']
    context['include_actions'] = asbool(data_dict.get('include_actions'))

    permissions = session.query(extmodel.Permission) \
        .filter_by(state='active') \
        .all()
    return dictization.permission_list_dictize(permissions, context)
