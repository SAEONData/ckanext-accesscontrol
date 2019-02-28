# encoding: utf-8

import logging
from paste.deploy.converters import asbool

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckanext.accesscontrol.logic import schema
from ckanext.accesscontrol.lib import dictization
import ckanext.accesscontrol.model as extmodel
from ckanext.accesscontrol.logic import is_permission_action_automatic

log = logging.getLogger(__name__)


@tk.side_effect_free
def user_privilege_check(context, data_dict):
    """
    Check whether a user has the privilege (via user roles and role permissions)
    to perform an action.

    You must be a sysadmin to check user privileges.

    :param user_id: the id or name of the user
    :type user_id: string
    :param action_name: the name of the action API function
    :type action_name: string

    :returns: boolean
    """
    log.debug("Checking user privilege: %r", data_dict)
    tk.check_access('user_privilege_check', context, data_dict)

    model = context['model']
    session = context['session']

    user_id, action_name = tk.get_or_bust(data_dict, ['user_id', 'action_name'])
    try:
        tk.get_action(action_name)
    except:
        raise tk.ValidationError({'action_name': [_('The action %s does not exist') % action_name]})

    if is_permission_action_automatic(action_name):
        return True

    user = model.User.get(user_id)
    if user is not None and user.state == 'active':
        user_id = user.id
    else:
        return False

    if user.sysadmin:
        return True

    has_privilege = session.query(extmodel.UserRole).join(extmodel.Role).join(extmodel.RolePermission) \
        .join(extmodel.PermissionAction, extmodel.PermissionAction.permission_id == extmodel.RolePermission.permission_id) \
        .filter(extmodel.UserRole.user_id == user_id) \
        .filter(extmodel.UserRole.state == 'active') \
        .filter(extmodel.Role.state == 'active') \
        .filter(extmodel.RolePermission.state == 'active') \
        .filter(extmodel.PermissionAction.action_name == action_name) \
        .count() > 0
    return has_privilege


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
    Grant a role the permission to perform an action.

    You must be a sysadmin to grant permissions.

    :param role_id: the id or name of the role
    :type role_id: string
    :param action_name: the name of the action API function
    :type action_name: string
    """
    log.info("Granting permission to role: %r", data_dict)
    tk.check_access('role_permission_grant', context, data_dict)

    model = context['model']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    role_id, action_name = tk.get_or_bust(data_dict, ['role_id', 'action_name'])
    role = extmodel.Role.get(role_id)
    if role is not None and role.state == 'active':
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    try:
        tk.get_action(action_name)
    except:
        raise tk.ValidationError({'action_name': [_('The action %s does not exist') % action_name]})

    role_permission = extmodel.RolePermission.lookup(role_id, action_name)
    if role_permission and role_permission.state == 'active':
        raise tk.ValidationError(_('The specified permission has already been granted to the role'))

    data_dict['role_id'] = role_id
    dictization.role_permission_dict_save(data_dict, context)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Grant permission to role %s: %s') % (role.name, action_name)

    if not defer_commit:
        model.repo.commit()


def role_permission_revoke(context, data_dict):
    """
    Revoke a role's permission to perform an action.

    You must be a sysadmin to revoke permissions.

    :param role_id: the id or name of the role
    :type role_id: string
    :param action_name: the name of the action API function
    :type action_name: string
    """
    log.info("Revoking permission from role: %r", data_dict)
    tk.check_access('role_permission_revoke', context, data_dict)

    model = context['model']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    role_id, action_name = tk.get_or_bust(data_dict, ['role_id', 'action_name'])
    role = extmodel.Role.get(role_id)
    if role is not None and role.state == 'active':
        role_id = role.id
    else:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Role')))

    try:
        tk.get_action(action_name)
    except:
        raise tk.ValidationError({'action_name': [_('The action %s does not exist') % action_name]})

    role_permission = extmodel.RolePermission.lookup(role_id, action_name)
    if not role_permission or role_permission.state != 'active':
        raise tk.ValidationError(_('The role does not have the specified permission'))

    role_permission.delete()

    rev = model.repo.new_revision()
    rev.author = user
    rev.message = _(u'REST API: Revoke permission from role %s: %s') % (role.name, action_name)

    if not defer_commit:
        model.repo.commit()


@tk.side_effect_free
def role_permission_list(context, data_dict):
    """
    Return a list of permissions for a role.

    You must be a sysadmin to list role permissions.

    :param role_id: the id or name of the role
    :type role_id: string

    :returns: list of action names
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

    permissions = session.query(extmodel.Permission).join(extmodel.RolePermission) \
        .filter_by(role_id=role_id, state='active') \
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
    dictization.user_role_dict_save(data_dict, context)

    rev = model.repo.new_revision()
    rev.author = author
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Assign role %s to user %s') % (role.name, user.name)

    if not defer_commit:
        model.repo.commit()


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
    if role is not None and role.state == 'active':
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


def permission_create(context, data_dict):
    """
    Create a permission definition, and optionally associate action(s) with it.

    A permission consists of an operation on a content type, e.g. 'edit' on
    'dataset'. Such a permission may be associated with one or more actions,
    e.g. 'package_update', 'resource_update', and 'package_relationship_update'.

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: identifies a conceptual object type, which might represent
        one or more underlying domain object types, or even a partition of an underlying
        domain object type (e.g. a specific 'type' of package or group)
    :type content_type: string
    :param operation: identifies a conceptual action, e.g. 'create', 'read', 'validate'
    :type operation: string
    :param actions: names of action functions to be associated with the given content
        type and operation (optional)
    :type actions: list of strings
    """
    log.info("Creating permission: %r", data_dict)
    tk.check_access('permission_create', context, data_dict)

    model = context['model']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    data, errors = tk.navl_validate(data_dict, schema.permission_create_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    permission = dictization.permission_dict_save(data, context)
    action_list = data.get('actions')
    if action_list:
        context['permission'] = permission
        dictization.permission_action_list_save(action_list, context)

    if not defer_commit:
        model.repo.commit()


def permission_delete(context, data_dict):
    """
    Delete a permission definition and associated permission actions.

    Note that this cascades to related role permissions.

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: the permission content type
    :type content_type: string
    :param operation: the permission operation
    :type operation: string
    """
    log.info("Deleting permission: %r", data_dict)
    tk.check_access('permission_delete', context, data_dict)

    model = context['model']
    session = context['session']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    content_type, operation = tk.get_or_bust(data_dict, ['content_type', 'operation'])

    permission = extmodel.Permission.lookup(content_type, operation)
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    # delete associated permission actions
    permission_actions = session.query(extmodel.PermissionAction) \
        .filter_by(permission_id=permission.id) \
        .all()
    for permission_action in permission_actions:
        permission_action.delete()

    # cascade delete to role permissions
    role_permissions = session.query(extmodel.RolePermission) \
        .filter_by(permission_id=permission.id) \
        .filter_by(state='active') \
        .all()
    if role_permissions:
        rev = model.repo.new_revision()
        rev.author = user
        rev.message = _("Delete permission '%s' on '%s'") % (operation, content_type)
        for role_permission in role_permissions:
            role_permission.delete()

    permission.delete()

    if not defer_commit:
        model.repo.commit()


def permission_action_assign(context, data_dict):
    """
    Associate one or more action functions with a permission.

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: the permission content type
    :type content_type: string
    :param operation: the permission operation
    :type operation: string
    :param actions: names of action functions to be associated with the permission
    :type actions: list of strings
    """
    log.info("Assigning actions to permission: %r", data_dict)
    tk.check_access('permission_action_assign', context, data_dict)

    model = context['model']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    data, errors = tk.navl_validate(data_dict, schema.permission_action_assign_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    permission = extmodel.Permission.lookup(data['content_type'], data['operation'])
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    context['permission'] = permission
    dictization.permission_action_list_save(data['actions'], context)

    if not defer_commit:
        model.repo.commit()


def permission_action_unassign(context, data_dict):
    """
    Dissociate one or more action functions from a permission.

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: the permission content type
    :type content_type: string
    :param operation: the permission operation
    :type operation: string
    :param actions: names of action functions to be dissociated from the permission
    :type actions: list of strings
    """
    log.info("Unassigning actions from permission: %r", data_dict)
    tk.check_access('permission_action_unassign', context, data_dict)

    model = context['model']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    data, errors = tk.navl_validate(data_dict, schema.permission_action_unassign_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    permission = extmodel.Permission.lookup(data['content_type'], data['operation'])
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    for action in data['actions']:
        permission_action = session.query(extmodel.PermissionAction) \
            .filter_by(permission_id=permission.id, action_name=action) \
            .first()
        if permission_action:
            permission_action.delete()

    if not defer_commit:
        model.repo.commit()


@tk.side_effect_free
def permission_show(context, data_dict):
    """
    Return a permission definition.

    You must be a sysadmin to view permissions.

    :param id: the id of the permission
    :type id: string

    :rtype: dictionary
    """
    log.debug("Retrieving permission: %r", data_dict)

    permission_id = tk.get_or_bust(data_dict, 'id')
    permission = extmodel.Permission.get(permission_id)
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    tk.check_access('permission_show', context, data_dict)

    context['include_actions'] = True
    return dictization.permission_dictize(permission, context)


@tk.side_effect_free
def permission_list(context, data_dict):
    """
    Return a list of the site's permissions.

    You must be a sysadmin to list permissions.

    :rtype: list of dicts
    """
    log.debug("Retrieving permission list: %r", data_dict)
    tk.check_access('permission_list', context, data_dict)

    session = context['session']
    context['include_actions'] = True
    permissions = session.query(extmodel.Permission).all()
    return dictization.permission_list_dictize(permissions, context)
