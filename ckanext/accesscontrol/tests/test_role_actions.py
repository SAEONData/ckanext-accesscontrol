# encoding: utf-8

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
