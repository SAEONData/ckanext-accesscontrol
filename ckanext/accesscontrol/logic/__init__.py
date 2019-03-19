# encoding: utf-8

_default_allow_actions = (
    'site_read',
    'user_create',
    'sysadmin',  # pseudo-action that CKAN calls check_access for
)


def is_action_allowed_by_default(action_name):
    """
    Indicates whether the given action does not require an explicit role permission.
    :returns: boolean
    """
    return action_name in _default_allow_actions
