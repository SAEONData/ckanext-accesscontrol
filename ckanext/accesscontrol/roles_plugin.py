# encoding: utf-8

import ckan.plugins as p
import ckan.logic
import ckan.plugins.toolkit as tk
from ckanext.accesscontrol.logic import action, auth, permission_setup_actions
from ckanext.accesscontrol.config import config as accesscontrol_config


class RolesPlugin(p.SingletonPlugin):

    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IPluginObserver, inherit=True)
    p.implements(p.IActions)
    p.implements(p.IAuthFunctions)
    p.implements(p.IConfigurer)
    p.implements(p.IConfigurable)

    # pointer to the check_access function in core CKAN
    core_check_access = None

    def before_map(self, map):
        """
        Configure routes.
        """
        with map.submapper(controller='ckanext.accesscontrol.controllers.role:RoleController') as m:
            m.connect('role_index', '/role', action='index')
            m.connect('role_new', '/role/new', action='new')
            m.connect('role_edit', '/role/edit/{id}', action='edit', ckan_icon='pencil-square-o')
            m.connect('role_delete', '/role/delete/{id}', action='delete')
            m.connect('role_read', '/role/{id}', action='read', ckan_icon='shield')
            m.connect('role_about', '/role/about/{id}', action='about', ckan_icon='info-circle')
            m.connect('role_activity', '/role/activity/{id}', action='activity', ckan_icon='clock-o')
            m.connect('role_permissions', '/role/permissions/{id}', action='permissions', ckan_icon='shield')

        return map

    def check_access(self, action_name, context, data_dict=None):
        """
        Check whether the user has the privilege to perform the named action,
        before calling the core check_access function.
        """
        check_auth = not context.get('ignore_auth', False)
        if check_auth:
            check_context = context.copy()
            check_context.setdefault('session', check_context['model'].Session)  # because ckan.lib.helpers.check_access does not add the session to the context *smh*
            check_data_dict = {
                'user_id': context['user'],
                'action': action_name,
            }
            privilege_check = action.user_privilege_check(check_context, check_data_dict)
            if not privilege_check['success']:
                raise tk.NotAuthorized(privilege_check['msg'])

        return self.core_check_access(action_name, context, data_dict)

    def after_load(self, service):
        """
        Chain our check_access method onto CKAN's when the plugin is loaded.
        """
        if self.core_check_access is None:
            self.core_check_access = ckan.logic.check_access
            # Hack alert!
            # this is the only way to ensure that all core check_access calls come to self.check_access
            tk.check_access = \
                ckan.logic.check_access = \
                ckan.logic.action.get._check_access = \
                ckan.logic.action.create._check_access = \
                ckan.logic.action.update._check_access = \
                ckan.logic.action.delete._check_access = \
                self.check_access

    def after_unload(self, service):
        """
        Un-chain our check_access method from CKAN's when the plugin is unloaded.
        """
        if self.core_check_access is not None:
            # Hack alert!
            # revert all core check_access references
            tk.check_access = \
                ckan.logic.check_access = \
                ckan.logic.action.get._check_access = \
                ckan.logic.action.create._check_access = \
                ckan.logic.action.update._check_access = \
                ckan.logic.action.delete._check_access = \
                self.core_check_access
            self.core_check_access = None

    def get_actions(self):
        return {
            'user_privilege_check': action.user_privilege_check,
            'role_create': action.role_create,
            'role_update': action.role_update,
            'role_delete': action.role_delete,
            'role_show': action.role_show,
            'role_list': action.role_list,
            'role_permission_grant': action.role_permission_grant,
            'role_permission_revoke': action.role_permission_revoke,
            'role_permission_list': action.role_permission_list,
            'user_role_assign': action.user_role_assign,
            'user_role_unassign': action.user_role_unassign,
            'permission_list': action.permission_list,
            'permission_define': permission_setup_actions.permission_define,
            'permission_undefine': permission_setup_actions.permission_undefine,
            'permission_delete_all': permission_setup_actions.permission_delete_all,
        }

    def get_auth_functions(self):
        return {
            'user_privilege_check': auth.user_privilege_check,
            'role_create': auth.role_create,
            'role_update': auth.role_update,
            'role_delete': auth.role_delete,
            'role_show': auth.role_show,
            'role_list': auth.role_list,
            'role_permission_grant': auth.role_permission_grant,
            'role_permission_revoke': auth.role_permission_revoke,
            'role_permission_list': auth.role_permission_list,
            'user_role_assign': auth.user_role_assign,
            'user_role_unassign': auth.user_role_unassign,
            'permission_list': auth.permission_list,
            'permission_define': auth.permission_define,
            'permission_undefine': auth.permission_undefine,
            'permission_delete_all': auth.permission_delete_all,
        }

    def update_config(self, config):
        tk.add_template_directory(config, 'templates')
        tk.add_public_directory(config, 'public')

    def configure(self, config):
        accesscontrol_config.load_common_options()
