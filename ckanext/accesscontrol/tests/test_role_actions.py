# encoding: utf-8

from ckanext.accesscontrol import model as extmodel
from ckanext.accesscontrol.tests import (
    ActionTestBase,
    assert_object_matches_dict,
    assert_error,
    factories as ckanext_factories,
)


class TestRoleActions(ActionTestBase):

    def test_create_valid(self):
        input_dict = {
            'name': 'test-role',
            'title': 'Test Role',
            'description': 'This is a test role',
        }
        result, obj = self.test_action('role_create', **input_dict)
        assert_object_matches_dict(obj, input_dict)

    def test_create_invalid_duplicate_name(self):
        role = ckanext_factories.Role()
        result, obj = self.test_action('role_create', should_error=True,
                                       name=role['name'])
        assert_error(result, 'name', 'Duplicate name')

    def test_create_invalid_sysadmin_name(self):
        result, obj = self.test_action('role_create', should_error=True,
                                       name='sysadmin')
        assert_error(result, 'name', "The name 'sysadmin' is reserved for the built-in system administrator role.")

    def test_create_invalid_missing_name(self):
        result, obj = self.test_action('role_create', should_error=True,
                                       name='')
        assert_error(result, 'name', 'Missing value')

    def test_update_valid(self):
        role = ckanext_factories.Role()
        input_dict = {
            'id': role['id'],
            'name': 'updated-test-role',
            'title': 'Updated Test Role',
            'description': 'Updated test role',
        }
        result, obj = self.test_action('role_update', **input_dict)
        assert_object_matches_dict(obj, input_dict)

    def test_update_valid_partial(self):
        role = ckanext_factories.Role()
        input_dict = {
            'id': role['id'],
            'title': 'Updated Test Role',
        }
        result, obj = self.test_action('role_update', **input_dict)
        assert obj.title == input_dict['title']
        assert obj.name == role['name']
        assert obj.description == role['description']

    def test_update_invalid_duplicate_name(self):
        role1 = ckanext_factories.Role()
        role2 = ckanext_factories.Role()
        input_dict = {
            'id': role1['id'],
            'name': role2['name'],
        }
        result, obj = self.test_action('role_update', should_error=True, **input_dict)
        assert_error(result, 'name', 'Duplicate name')

    def test_update_invalid_sysadmin_name(self):
        role = ckanext_factories.Role()
        result, obj = self.test_action('role_update', should_error=True,
                                       id=role['id'],
                                       name='sysadmin')
        assert_error(result, 'name', "The name 'sysadmin' is reserved for the built-in system administrator role.")

    def test_delete_valid(self):
        role = ckanext_factories.Role()
        self.test_action('role_delete', id=role['id'])

    def test_permission_grant_valid(self):
        role = ckanext_factories.Role()
        permission = ckanext_factories.Permission()
        self.test_action('role_permission_grant',
                         role_id=role['name'],
                         permission_id=permission['id'])
        role_permission = extmodel.RolePermission.lookup(role['id'], permission['id'])
        assert role_permission and role_permission.state == 'active'

    def test_permission_grant_invalid_already_granted(self):
        role_permission = ckanext_factories.RolePermission()
        result, _ = self.test_action('role_permission_grant', should_error=True,
                                     role_id=role_permission['role_id'],
                                     permission_id=role_permission['permission_id'])
        assert_error(result, 'message', 'The specified permission has already been granted to the role')

    def test_permission_revoke_valid(self):
        role_permission = ckanext_factories.RolePermission()
        role = extmodel.Role.get(role_permission['role_id'])
        self.test_action('role_permission_revoke',
                         role_id=role.name,
                         permission_id=role_permission['permission_id'])
        role_permission = extmodel.RolePermission.lookup(role.id, role_permission['permission_id'])
        assert role_permission.state == 'deleted'

    def test_permission_revoke_invalid_not_granted(self):
        role = ckanext_factories.Role()
        permission = ckanext_factories.Permission()
        result, _ = self.test_action('role_permission_revoke',
                                     role_id=role['name'],
                                     permission_id=permission['id'])
        assert_error(result, 'message', 'The role does not have the specified permission')
