# encoding: utf-8

from ckan import model
from ckanext.accesscontrol import model as extmodel
from ckanext.accesscontrol.tests import (
    ActionTestBase,
    assert_error,
    factories as ckanext_factories,
)


class TestPermissionSetupActions(ActionTestBase):

    @staticmethod
    def _check_permission(**data_dict):
        permission = model.Session.query(extmodel.Permission) \
            .filter_by(content_type=data_dict['content_type'], operation=data_dict['operation']) \
            .first()
        assert permission is not None
        permission_actions = model.Session.query(extmodel.PermissionAction.action_name) \
            .filter_by(permission_id=permission.id) \
            .all()
        actions = [action for (action,) in permission_actions]
        assert set(actions) == set(data_dict['actions'])

    def test_define_valid_new(self):
        input_dict = {
            'content_type': 'stuff',
            'operation': 'do',
            'actions': ['resource_update', 'resource_view_update'],
        }
        self.test_action('permission_define', **input_dict)
        self._check_permission(**input_dict)

    def test_define_valid_add(self):
        permission = ckanext_factories.Permission()
        input_dict = {
            'content_type': permission['content_type'],
            'operation': permission['operation'],
            'actions': ['resource_update', 'resource_view_update'],
        }
        self.test_action('permission_define', **input_dict)
        input_dict['actions'] += permission['actions']
        self._check_permission(**input_dict)

    def test_define_invalid_missing_values(self):
        result, _ = self.test_action('permission_define', should_error=True,
                                     content_type='',
                                     operation='',
                                     actions=[])
        assert_error(result, 'content_type', 'Missing value')
        assert_error(result, 'operation', 'Missing value')
        assert_error(result, 'actions', 'Missing value')

    def test_define_invalid_action_list(self):
        result, _ = self.test_action('permission_define', should_error=True,
                                     actions=[1,])
        assert_error(result, 'actions', 'Not a string')

    def test_define_invalid_action_not_exist(self):
        result, _ = self.test_action('permission_define', should_error=True,
                                     actions=['foo', 'package_create', 'bar'])
        assert_error(result, 'actions', 'The action foo does not exist')
        assert_error(result, 'actions', 'The action bar does not exist')

    def test_undefine_valid_full(self):
        permission = ckanext_factories.Permission()
        self.test_action('permission_undefine',
                         content_type=permission['content_type'],
                         operation=permission['operation'],
                         actions=permission['actions'])
        permission['actions'] = []
        self._check_permission(**permission)

    def test_undefine_valid_partial(self):
        permission = ckanext_factories.Permission()
        self.test_action('permission_undefine',
                         content_type=permission['content_type'],
                         operation=permission['operation'],
                         actions=permission['actions'][:-1])
        del permission['actions'][0]
        self._check_permission(**permission)

    def test_undefine_valid_action_not_exist(self):
        # allow removal of non-existent actions because they might have been deprecated
        permission = ckanext_factories.Permission()
        permission_action = extmodel.PermissionAction(permission_id=permission['id'], action_name='does_not_exist')
        model.Session.add(permission_action)
        model.repo.commit()
        data_dict = {
            'content_type': permission['content_type'],
            'operation': permission['operation'],
            'actions': permission['actions'] + ['does_not_exist'],
        }
        self._check_permission(**data_dict)

        self.test_action('permission_undefine',
                         content_type=permission['content_type'],
                         operation=permission['operation'],
                         actions=['does_not_exist'])
        data_dict['actions'].remove('does_not_exist')
        self._check_permission(**data_dict)

    def test_undefine_invalid_missing_values(self):
        result, _ = self.test_action('permission_undefine', should_error=True,
                                     content_type='',
                                     operation='',
                                     actions=[])
        assert_error(result, 'content_type', 'Missing value')
        assert_error(result, 'operation', 'Missing value')
        assert_error(result, 'actions', 'Missing value')

    def test_undefine_invalid_action_list(self):
        result, _ = self.test_action('permission_undefine', should_error=True,
                                     actions=[1,])
        assert_error(result, 'actions', 'Not a string')

    def test_delete_all(self):
        ckanext_factories.Permission()
        ckanext_factories.Permission()
        assert model.Session.query(extmodel.Permission).count() > 0
        assert model.Session.query(extmodel.PermissionAction).count() > 0
        self.test_action('permission_delete_all')
        assert model.Session.query(extmodel.Permission).count() == 0
        assert model.Session.query(extmodel.PermissionAction).count() == 0
