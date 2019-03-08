# encoding: utf-8

from ckan import model
from ckan.tests.helpers import call_action
from ckan.tests import factories as ckan_factories
from ckanext.accesscontrol import model as extmodel
from ckanext.accesscontrol.logic import _actions_with_automatic_permission
from ckanext.accesscontrol.tests import (
    ActionTestBase,
    assert_error,
    factories as ckanext_factories,
)


class TestUserPrivilegeActions(ActionTestBase):

    def _prepare_user_privilege(self):
        self.user = ckan_factories.User()
        self.role = ckanext_factories.Role()
        self.user_role = ckanext_factories.UserRole(role_id=self.role['id'], user_id=self.user['id'])
        self.permission = ckanext_factories.Permission()
        self.role_permission = ckanext_factories.RolePermission(role_id=self.role['id'], permission_id=self.permission['id'])

    def test_valid(self):
        self._prepare_user_privilege()
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is True
        assert_error(result, 'msg', 'User is permitted to perform the action')

    def test_deleted_role(self):
        self._prepare_user_privilege()
        call_action('role_delete', id=self.role['id'])
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_revoked_permission(self):
        self._prepare_user_privilege()
        call_action('role_permission_revoke', role_id=self.role['id'], permission_id=self.permission['id'])
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_unassigned_role(self):
        self._prepare_user_privilege()
        call_action('user_role_unassign', role_id=self.role['id'], user_id=self.user['id'])
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_undefined_permission(self):
        self._prepare_user_privilege()
        call_action('permission_undefine',
                    content_type=self.permission['content_type'],
                    operation=self.permission['operation'],
                    actions=self.permission['actions'][0:1])
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_cleaned_up_permission(self):
        self._prepare_user_privilege()
        call_action('permission_undefine',
                    content_type=self.permission['content_type'],
                    operation=self.permission['operation'],
                    actions=self.permission['actions'])
        call_action('permission_cleanup')
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_deleted_permission(self):
        self._prepare_user_privilege()
        permission = extmodel.Permission.get(self.permission['id'])
        permission.delete()
        model.repo.commit()
        result, _ = self.test_action('user_privilege_check',
                                     action=self.permission['actions'][0],
                                     user_id=self.user['name'])
        assert result['success'] is False
        assert_error(result, 'msg', 'User is not permitted to perform the action')

    def test_missing_values(self):
        result, _ = self.test_action('user_privilege_check', should_error=True)
        assert_error(result, 'user_id', 'Missing value')
        assert_error(result, 'action', 'Missing value')

    def test_invalid_action(self):
        result, _ = self.test_action('user_privilege_check', should_error=True,
                                     action='foo',
                                     user_id='')
        assert_error(result, 'action', 'The action foo does not exist')

    def test_invalid_user(self):
        result, _ = self.test_action('user_privilege_check',
                                     action='package_create',
                                     user_id='foo')
        assert result['success'] is False
        assert_error(result, 'msg', 'Unknown user')

    def test_deleted_user(self):
        user = ckan_factories.User()
        call_action('user_delete', id=user['id'])
        result, _ = self.test_action('user_privilege_check',
                                     action='package_create',
                                     user_id=user['id'])
        assert result['success'] is False
        assert_error(result, 'msg', 'Unknown user')

    def test_sysadmin_user(self):
        user = ckan_factories.Sysadmin()
        result, _ = self.test_action('user_privilege_check',
                                     action='package_create',
                                     user_id=user['id'])
        assert result['success'] is True
        assert_error(result, 'msg', 'User is a sysadmin')

    def test_automatic_privilege(self):
        for action in _actions_with_automatic_permission:
            result, _ = self.test_action('user_privilege_check',
                                         action=action,
                                         user_id='')
            assert result['success'] is True
            assert_error(result, 'msg', 'The action %s is allowed by default' % action)
