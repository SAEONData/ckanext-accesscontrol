# encoding: utf-8

_actions_with_automatic_permission = (
    'site_read',
    'user_create',
)


def is_action_permission_automatic(action_name):
    return action_name in _actions_with_automatic_permission
