# encoding: utf-8

import uuid
import re
import json
from collections import deque
import traceback
from nose.tools import nottest

from ckan.tests import factories as ckan_factories
from ckan.tests.helpers import FunctionalTestBase, call_action, reset_db
import ckan.plugins.toolkit as tk
import ckan.model as ckan_model
from ckanext.accesscontrol.model import setup_roles
from ckanext.accesscontrol import model as extmodel

_model_map = {
    'user_role': extmodel.UserRole,
    'role': extmodel.Role,
    'role_permission': extmodel.RolePermission,
    'permission': extmodel.Permission,
    'permission_action': extmodel.PermissionAction,
}


def make_uuid():
    return unicode(uuid.uuid4())


def generate_name(*strings):
    """
    Converts the given string(s) into a form suitable for an object name.
    """
    strings = list(strings)
    while '' in strings:
        strings.remove('')
    text = '-'.join(strings)
    return re.sub(r'[^a-z0-9_-]+', '-', text.lower())


def assert_object_matches_dict(object_, dict_, json_values=()):
    """
    Check that the object has all the items in the dict.
    """
    for key in dict_.keys():
        # any kind of empty matches any kind of empty
        dict_value = dict_[key] or None
        object_value = getattr(object_, key) or None
        if key in json_values:
            if isinstance(dict_value, basestring):
                dict_value = json.loads(dict_value)
            object_value = json.loads(object_value)
        assert dict_value == object_value


def assert_error(error_dict, key, pattern):
    """
    Check that the error dictionary contains the given key with the corresponding error message regex.
    Key may be in JSON pointer format (e.g. 'infrastructures/0/id').
    """
    def has_error(node, path):
        if path:
            index = path.popleft()
            if type(node) is list:
                index = int(index)
            return has_error(node[index], path)
        elif type(node) is list:
            return next((True for msg in node if re.search(pattern, msg) is not None), False)
        elif isinstance(node, basestring):
            return re.search(pattern, node) is not None
        return False

    error_path = deque(key.split('/')) if key else None
    try:
        assert has_error(error_dict, error_path)
    except KeyError:
        assert False, "'{}' not found in error dict".format(key)


class ActionTestBase(FunctionalTestBase):

    _load_plugins = 'roles',

    @classmethod
    def setup_class(cls):
        print "\n===", cls.__name__, "==="
        super(ActionTestBase, cls).setup_class()
        setup_roles.init_tables()

    @classmethod
    def teardown_class(cls):
        super(ActionTestBase, cls).teardown_class()
        # we just want to ensure that after the very last class teardown, we don't leave
        # anything in the DB that might cause FK violations when initializing the first
        # set of tests in another extension
        reset_db()

    def setup(self):
        super(ActionTestBase, self).setup()
        # hack because CKAN doesn't clean up the session properly
        if hasattr(ckan_model.Session, 'revision'):
            delattr(ckan_model.Session, 'revision')
        self.normal_user = ckan_factories.User()
        self.sysadmin_user = ckan_factories.Sysadmin()

    @nottest
    def test_action(self, action_name, should_error=False, exception_class=tk.ValidationError,
                    sysadmin=False, check_auth=False, **kwargs):
        """
        Test an API action.
        :param action_name: action function name, e.g. 'metadata_record_create'
        :param should_error: True if this test should raise an exception, False otherwise
        :param exception_class: the type of exception to be expected if should_error is True
        :param sysadmin: True to execute the action as a sysadmin, False to run it as a normal user
        :param check_auth: True to check whether the user is authorized to perform the action,
            False to ignore the auth check
        :param kwargs: additional args to pass to the action function
        :return: tuple(result dict, result obj)
        """
        model, method = action_name.rsplit('_', 1)
        model_class = _model_map.get(model)
        user = self.sysadmin_user if sysadmin else self.normal_user
        context = {
            'user': user['name'],
            'ignore_auth': not check_auth,
        }

        obj = None
        try:
            result = call_action(action_name, context, **kwargs)
        except exception_class, e:
            if exception_class is tk.ValidationError:
                result = e.error_dict
            else:
                result = e.message
        except Exception, e:
            traceback.print_exc()
            assert False, "Unexpected exception %s: %s" % (type(e), e)
        else:
            if should_error:
                assert False, str(exception_class) + " was not raised"
        finally:
            # close the session to ensure that we're not just getting the obj from
            # memory but are reloading it from the DB
            ckan_model.Session.close_all()

        if not should_error and model_class is not None:
            if method in ('create', 'update', 'show'):
                assert 'id' in result
                obj = model_class.get(result['id'])
                assert type(obj) is model_class
                assert obj.state == 'active'
            elif method == 'delete':
                obj = model_class.get(kwargs['id'])
                assert obj.state == 'deleted'
            elif 'id' in kwargs:
                obj = model_class.get(kwargs['id'])

        return result, obj
