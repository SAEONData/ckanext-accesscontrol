# encoding: utf-8

import ckan.plugins.toolkit as tk
import ckan.model as model
import ckan.lib.helpers as helpers
from ckan.logic import clean_dict, tuplize_dict, parse_params
import ckan.lib.navl.dictization_functions as dict_fns


class RoleController(tk.BaseController):

    def index(self):
        page = tk.h.get_page_number(tk.request.params) or 1
        items_per_page = 21

        context = {'model': model, 'session': model.Session, 'user': tk.c.user}

        q = tk.c.q = tk.request.params.get('q', '')
        sort_by = tk.c.sort_by_selected = tk.request.params.get('sort')
        try:
            tk.check_access('role_list', context)
        except tk.NotAuthorized:
            tk.abort(403, tk._('Not authorized to see this page'))

        if tk.c.userobj:
            context['user_id'] = tk.c.userobj.id
            context['user_is_admin'] = tk.c.userobj.sysadmin

        try:
            data_dict_global_results = {
                'all_fields': False,
                'q': q,
                'sort': sort_by,
                'type': 'role',
            }
            global_results = tk.get_action('role_list')(context, data_dict_global_results)
        except tk.ValidationError as e:
            if e.error_dict and e.error_dict.get('message'):
                msg = e.error_dict['message']
            else:
                msg = str(e)
            tk.h.flash_error(msg)
            tk.c.page = helpers.Page([], 0)
            return tk.render('role/index.html')

        data_dict_page_results = {
            'all_fields': True,
            'q': q,
            'sort': sort_by,
            'limit': items_per_page,
            'offset': items_per_page * (page - 1),
        }
        page_results = tk.get_action('role_list')(context, data_dict_page_results)

        tk.c.page = helpers.Page(
            collection=global_results,
            page=page,
            url=tk.h.pager_url,
            items_per_page=items_per_page,
        )

        tk.c.page.items = page_results
        return tk.render('role/index.html')

    def new(self, data=None, errors=None, error_summary=None):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user,
                   'save': 'save' in tk.request.params}

        if context['save'] and not data and tk.request.method == 'POST':
            return self._save_new(context)

        try:
            tk.check_access('role_create', context)
        except tk.NotAuthorized:
            tk.abort(403, tk._('Not authorized to create roles'))

        data = data or {}
        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary, 'action': 'new'}

        tk.c.form = tk.render('role/edit_form.html', extra_vars=vars)
        return tk.render('role/edit.html', extra_vars=vars)

    def edit(self, id, data=None, errors=None, error_summary=None):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user,
                   'save': 'save' in tk.request.params, 'for_edit': True}
        data_dict = {'id': id}

        if context['save'] and not data and tk.request.method == 'POST':
            return self._save_edit(id, context)

        try:
            old_data = tk.get_action('role_show')(context, data_dict)
            data = data or old_data
        except (tk.ObjectNotFound, tk.NotAuthorized):
            tk.abort(404, tk._('Role not found'))

        tk.c.role = old_data
        try:
            tk.check_access('role_update', context)
        except tk.NotAuthorized:
            tk.abort(403, tk._('User %r not authorized to edit %s') % (tk.c.user, id))

        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary, 'action': 'edit'}

        tk.c.form = tk.render('role/edit_form.html', extra_vars=vars)
        return tk.render('role/edit.html', extra_vars=vars)

    def delete(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user}
        try:
            if tk.request.method == 'POST':
                tk.get_action('role_delete')(context, {'id': id})
                tk.h.flash_notice(tk._('Role has been deleted.'))
                tk.h.redirect_to('role_index')
        except tk.NotAuthorized:
            tk.abort(403, tk._('Unauthorized to delete role'))
        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))

    def read(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user}
        tk.c.role = tk.get_action('role_show')(context, {'id': id})
        tk.c.permissions = tk.get_action('role_permission_list')(context, {'role_id': id})
        return tk.render('role/read.html')

    def about(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user}
        tk.c.role = tk.get_action('role_show')(context, {'id': id})
        return tk.render('role/about.html')

    def activity(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user}
        tk.c.role = tk.get_action('role_show')(context, {'id': id})
        return tk.render('role/activity_stream.html')

    def permissions(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user,
                   'save': 'save' in tk.request.params}

        try:
            tk.c.permissions = self._get_permission_list(id, context)
        except (tk.ObjectNotFound, tk.NotAuthorized):
            tk.abort(404, tk._('Role not found'))

        if context['save'] and tk.request.method == 'POST':
            return self._save_permissions(id, context)

        tk.c.role = tk.get_action('role_show')(context, {'id': id})
        tk.c.form = tk.render('role/permissions_form.html')
        return tk.render('role/permissions.html')

    def users(self, id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user,
                   'save': 'save' in tk.request.params}

        try:
            tk.c.users = self._get_user_list(id, context)
        except (tk.ObjectNotFound, tk.NotAuthorized):
            tk.abort(404, tk._('Role not found'))

        if context['save'] and tk.request.method == 'POST':
            user_id = tk.request.params.get('user_id')
            return self._assign_user_role(id, user_id, context)

        tk.c.role = tk.get_action('role_show')(context, {'id': id})
        return tk.render('role/users.html')

    def user_unassign(self, id, user_id):
        context = {'model': model, 'session': model.Session, 'user': tk.c.user}
        try:
            if tk.request.method == 'POST':
                tk.get_action('user_role_unassign')(context, {'role_id': id, 'user_id': user_id})
                tk.h.flash_notice(tk._('The role has been unassigned from the user.'))
                tk.h.redirect_to('role_users', id=id)
        except tk.NotAuthorized:
            tk.abort(403, tk._('Unauthorized to unassign roles'))
        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))

    @staticmethod
    def _get_user_list(id, context):
        all_users = tk.get_action('user_list')(context, {'all_fields': False})
        assigned_users = tk.get_action('role_user_list')(context, {'role_id': id})
        user_list = []
        for user in all_users:
            user_list += [{
                'name': user,
                'assigned': user in assigned_users,
            }]
        user_list.sort()
        return user_list

    @staticmethod
    def _get_permission_list(id, context):
        all_permissions = tk.get_action('permission_list')(context, {})
        granted_permissions = tk.get_action('role_permission_list')(context, {'role_id': id})
        permission_list = []
        for available_permission in all_permissions:
            permission_list += [{
                'id': available_permission['id'],
                'content_type': available_permission['content_type'],
                'operation': available_permission['operation'],
                'granted': available_permission in granted_permissions,
            }]
        permission_list.sort()
        return permission_list

    def _save_new(self, context):
        try:
            data_dict = clean_dict(dict_fns.unflatten(tuplize_dict(parse_params(tk.request.params))))
            context['message'] = data_dict.get('log_message', '')
            role = tk.get_action('role_create')(context, data_dict)
            tk.h.redirect_to('role_read', id=role['name'])
        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))
        except tk.NotAuthorized, e:
            tk.abort(403, e.message)
        except dict_fns.DataError:
            tk.abort(400, tk._(u'Integrity Error'))
        except tk.ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.new(data_dict, errors, error_summary)

    def _save_edit(self, id, context):
        try:
            data_dict = clean_dict(dict_fns.unflatten(tuplize_dict(parse_params(tk.request.params))))
            data_dict['id'] = id
            context['message'] = data_dict.get('log_message', '')
            context['allow_partial_update'] = True
            tk.get_action('role_update')(context, data_dict)
            tk.h.redirect_to('role_read', id=id)
        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))
        except tk.NotAuthorized, e:
            tk.abort(403, e.message)
        except dict_fns.DataError:
            tk.abort(400, tk._(u'Integrity Error'))
        except tk.ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.edit(id, data_dict, errors, error_summary)

    def _save_permissions(self, id, context):
        try:
            data_dict = clean_dict(dict_fns.unflatten(tuplize_dict(parse_params(tk.request.params))))
            data_dict['role_id'] = id
            context['message'] = data_dict.get('log_message', '')
            context['defer_commit'] = True

            selected_permission_ids = [permission_id[11:] for permission_id in data_dict.iterkeys()
                                       if permission_id.startswith('permission:')]
            current_permissions = tk.c.permissions
            for permission in current_permissions:
                if permission['id'] in selected_permission_ids and not permission['granted']:
                    data_dict['permission_id'] = permission['id']
                    tk.get_action('role_permission_grant')(context, data_dict)
                elif permission['granted'] and permission['id'] not in selected_permission_ids:
                    data_dict['permission_id'] = permission['id']
                    tk.get_action('role_permission_revoke')(context, data_dict)

            model.repo.commit()
            tk.h.redirect_to('role_read', id=id)

        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))
        except tk.NotAuthorized, e:
            tk.abort(403, e.message)
        except dict_fns.DataError:
            tk.abort(400, tk._(u'Integrity Error'))

    def _assign_user_role(self, id, user_id, context):
        try:
            tk.get_action('user_role_assign')(context, {'role_id': id, 'user_id': user_id})
            tk.h.flash_notice(tk._('The role has been assigned to the user.'))
            tk.h.redirect_to('role_users', id=id)
        except tk.ObjectNotFound:
            tk.abort(404, tk._('Role not found'))
        except tk.NotAuthorized, e:
            tk.abort(403, e.message)
        except dict_fns.DataError:
            tk.abort(400, tk._(u'Integrity Error'))
