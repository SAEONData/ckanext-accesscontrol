# encoding: utf-8

import factory

from ckanext.accesscontrol import model as extmodel
from ckan.tests import helpers, factories as ckan_factories
from ckan.logic import _actions as all_actions
from ckanext.accesscontrol.logic import _default_allow_actions


class Role(factory.Factory):
    FACTORY_FOR = extmodel.Role

    name = factory.Sequence(lambda n: 'test_role_{0:02d}'.format(n))
    title = factory.LazyAttribute(lambda obj: obj.name.replace('_', ' ').title())
    description = 'A test description for this test role.'

    @classmethod
    def _build(cls, target_class, *args, **kwargs):
        raise NotImplementedError(".build() isn't supported in CKAN")

    @classmethod
    def _create(cls, target_class, *args, **kwargs):
        if args:
            assert False, "Positional args aren't supported, use keyword args."

        context = {'user': ckan_factories._get_action_user_name(kwargs)}

        return helpers.call_action('role_create', context=context, **kwargs)


class Permission(factory.Factory):
    FACTORY_FOR = extmodel.Permission

    _actions = list(set(all_actions.keys()) - set(_default_allow_actions))

    content_type = factory.Sequence(lambda n: 'a_thing_{0:02d}'.format(n))
    operation = 'an_operation'
    actions = factory.Sequence(lambda n: [Permission._actions[2*n], Permission._actions[2*n+1]])

    @classmethod
    def _build(cls, target_class, *args, **kwargs):
        raise NotImplementedError(".build() isn't supported in CKAN")

    @classmethod
    def _create(cls, target_class, *args, **kwargs):
        if args:
            assert False, "Positional args aren't supported, use keyword args."

        context = {'user': ckan_factories._get_action_user_name(kwargs)}

        return helpers.call_action('permission_define', context=context, **kwargs)


class RolePermission(factory.Factory):
    FACTORY_FOR = extmodel.RolePermission

    @classmethod
    def _build(cls, target_class, *args, **kwargs):
        raise NotImplementedError(".build() isn't supported in CKAN")

    @classmethod
    def _create(cls, target_class, *args, **kwargs):
        if args:
            assert False, "Positional args aren't supported, use keyword args."

        context = {'user': ckan_factories._get_action_user_name(kwargs)}
        role_id = kwargs.pop('role_id', None) or Role()['id']
        permission_id = kwargs.pop('permission_id', None) or Permission()['id']

        return helpers.call_action('role_permission_grant', context=context,
                                   role_id=role_id,
                                   permission_id=permission_id,
                                   **kwargs)


class UserRole(factory.Factory):
    FACTORY_FOR = extmodel.UserRole

    @classmethod
    def _build(cls, target_class, *args, **kwargs):
        raise NotImplementedError(".build() isn't supported in CKAN")

    @classmethod
    def _create(cls, target_class, *args, **kwargs):
        if args:
            assert False, "Positional args aren't supported, use keyword args."

        context = {'user': ckan_factories._get_action_user_name(kwargs)}
        role_id = kwargs.pop('role_id', None) or Role()['id']
        user_id = kwargs.pop('user_id', None) or ckan_factories.User()['id']

        return helpers.call_action('user_role_assign', context=context,
                                   role_id=role_id,
                                   user_id=user_id,
                                   **kwargs)
