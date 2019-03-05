# encoding: utf-8

import logging

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckanext.accesscontrol.logic import schema
import ckanext.accesscontrol.model as extmodel
from ckanext.accesscontrol.lib import dictization

log = logging.getLogger(__name__)


def permission_define(context, data_dict):
    """
    Create the relations defining a permission required for some action(s).

    A permission consists of an operation on a content type, e.g. 'edit' on
    'dataset'. Such a permission may be associated with one or more actions,
    e.g. 'package_update', 'resource_update', and 'package_relationship_update'.

    This function may be called multiple times for the same content_type/operation
    combo, each time the specified action names being added as permission actions,
    rather than replacing those already existing. This allows a given content_type/
    operation to be used for actions originating in different extensions.

    This function may also be called with different content_type/operation for the
    same action(s), in case multiple permissions are required for the given action(s).

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: identifies a conceptual object type, which might represent
        one or more underlying domain object types, or even a partition of an underlying
        domain object type (e.g. a specific 'type' of package or group)
    :type content_type: string
    :param operation: identifies a conceptual action, e.g. 'create', 'read', 'validate'
    :type operation: string
    :param actions: names of action functions to be associated with the given content
        type and operation
    :type actions: list of strings

    :returns: the new or updated permission with its associated actions
    :rtype: dictionary
    """
    log.info("Defining permission: %r", data_dict)
    tk.check_access('permission_define', context, data_dict)

    model = context['model']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    data, errors = tk.navl_validate(data_dict, schema.permission_define_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    # find permission or create new
    permission = session.query(extmodel.Permission) \
        .filter_by(content_type=data['content_type'], operation=data['operation']) \
        .first()
    if permission is None:
        permission = extmodel.Permission(content_type=data['content_type'], operation=data['operation'])
        session.add(permission)
        session.flush()  # so that we get the new permission id
    elif permission.state == 'deleted':
        permission.undelete()

    # create permission actions if they don't exist
    saved_actions = session.query(extmodel.PermissionAction) \
        .filter_by(permission_id=permission.id) \
        .filter(extmodel.PermissionAction.action_name.in_(data['actions'])) \
        .all()
    unsaved_action_names = data['actions']
    for saved_action in saved_actions:
        unsaved_action_names.remove(saved_action.action_name)
        if saved_action.state == 'deleted':
            saved_action.undelete()
    for action_name in unsaved_action_names:
        permission_action = extmodel.PermissionAction(permission_id=permission.id, action_name=action_name)
        session.add(permission_action)

    if not defer_commit:
        model.repo.commit()

    context['include_actions'] = True
    return dictization.permission_dictize(permission, context)


def permission_undefine(context, data_dict):
    """
    Delete the relations that define a permission for some action(s).

    This might be used, for example, if an action previously associated with a
    permission has been deprecated.

    Calls to this function should normally be scripted, or coded in an extension,
    rather than being made available in the UI.

    :param content_type: conceptual object type
    :type content_type: string
    :param operation: conceptual action
    :type operation: string
    :param actions: names of action functions to be dissociated from the given content
        type and operation
    :type actions: list of strings

    :returns: the updated permission with its remaining associated actions
    :rtype: dictionary
    """
    log.info("Undefining permission: %r", data_dict)
    tk.check_access('permission_undefine', context, data_dict)

    model = context['model']
    session = context['session']
    defer_commit = context.get('defer_commit', False)

    data, errors = tk.navl_validate(data_dict, schema.permission_undefine_schema(), context)
    if errors:
        session.rollback()
        raise tk.ValidationError(errors)

    # find permission
    permission = session.query(extmodel.Permission) \
        .filter_by(content_type=data['content_type'], operation=data['operation'], state='active') \
        .first()
    if permission is None:
        raise tk.ObjectNotFound('%s: %s' % (_('Not found'), _('Permission')))

    # remove permission actions
    permission_actions = session.query(extmodel.PermissionAction) \
        .filter_by(permission_id=permission.id, state='active') \
        .filter(extmodel.PermissionAction.action_name.in_(data['actions'])) \
        .all()
    for permission_action in permission_actions:
        permission_action.delete()

    if not defer_commit:
        model.repo.commit()

    context['include_actions'] = True
    return dictization.permission_dictize(permission, context)


def permission_cleanup(context, data_dict):
    """
    Delete (purge) permission objects that have no associated actions, and delete any
    dependent role permissions.
    """
    log.info("Cleaning up unused permissions", data_dict)
    tk.check_access('permission_cleanup', context, data_dict)

    model = context['model']
    session = context['session']
    user = context['user']
    defer_commit = context.get('defer_commit', False)

    unused_permissions = session.query(extmodel.Permission) \
        .filter(~session.query(extmodel.PermissionAction)
                .filter(extmodel.PermissionAction.permission_id == extmodel.Permission.id)
                .filter_by(state='active')
                .exists()) \
        .all()

    for permission in unused_permissions:
        role_permissions = session.query(extmodel.RolePermission) \
            .filter_by(permission_id=permission.id, state='active') \
            .all()

        if role_permissions:
            rev = model.repo.new_revision()
            rev.author = user
            rev.message = _("Delete permission '%s' on '%s'") % (permission.operation, permission.content_type)
            for role_permission in role_permissions:
                role_permission.delete()

        permission.delete()

    if not defer_commit:
        model.repo.commit()
