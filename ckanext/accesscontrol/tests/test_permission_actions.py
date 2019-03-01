# encoding: utf-8

from ckanext.accesscontrol.tests import (
    ActionTestBase,
    assert_object_matches_dict,
    assert_error,
    factories as ckanext_factories,
)


class TestPermissionActions(ActionTestBase):

    def test_create_valid(self):
        input_dict = {
            'content_type': 'something',
            'operation': 'do_stuff',
        }
        result, obj = self.test_action('permission_create', stateful=False, **input_dict)
        assert_object_matches_dict(obj, input_dict)

    def test_create_invalid_duplicate(self):
        permission = ckanext_factories.Permission()
        result, obj = self.test_action('permission_create', should_error=True, stateful=False,
                                       content_type=permission['content_type'],
                                       operation=permission['operation'])
        assert_error(result, '__after', 'Unique constraint violation')

    def test_delete_valid(self):
        permission = ckanext_factories.Permission()
        self.test_action('permission_delete', stateful=False,
                         id=permission['id'],
                         content_type=permission['content_type'],
                         operation=permission['operation'])
