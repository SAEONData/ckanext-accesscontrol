# encoding: utf-8

from ckan.logic import _actions

_actions_with_automatic_permission = (
    'site_read',
    'user_create',
)


def is_permission_action_automatic(action_name):
    """
    Indicates whether the given action does not require an explicit role permission.
    :returns: boolean
    """
    return action_name in _actions_with_automatic_permission


def available_actions():
    """
    Get a list of actions that may be granted to a role.
    :returns: list of strings
    """
    actions = set(_actions.keys()) - set(_actions_with_automatic_permission)
    return list(actions)
