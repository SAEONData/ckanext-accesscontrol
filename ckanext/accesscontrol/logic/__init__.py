# encoding: utf-8

_default_allow_actions = (
    'site_read',
    'user_create',
    'sysadmin',  # pseudo-action that CKAN calls check_access for
    'dashboard_new_activities_count',
    'dashboard_activity_list',
    'package_search',
    'organization_list_for_user',
    'organization_list',
    'group_list',
    'group_edit_permissions',  # another pseudo-action
)


def is_action_allowed_by_default(action_name):
    """
    Indicates whether the given action does not require an explicit role permission.
    :returns: boolean
    """
    return action_name in _default_allow_actions
