# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckanext.accesscontrol.logic import validators as v

not_empty = tk.get_validator('not_empty')
not_missing = tk.get_validator('not_missing')
ignore = tk.get_validator('ignore')
ignore_missing = tk.get_validator('ignore_missing')
name_validator = tk.get_validator('name_validator')
list_of_strings = tk.get_validator('list_of_strings')


def role_create_schema():
    schema = {
        'id': [ignore],
        'name': [not_missing, not_empty, unicode, name_validator, v.role_name_validator],
        'title': [ignore_missing, unicode],
        'description': [ignore_missing, unicode],
    }
    return schema


def role_update_schema():
    schema = {
        'id': [],
        'name': [ignore_missing, unicode, name_validator, v.role_name_validator],
        'title': [ignore_missing, unicode],
        'description': [ignore_missing, unicode],
    }
    return schema


def role_show_schema():
    schema = dict.fromkeys(role_create_schema(), [])
    schema['revision_id'] = []
    schema['display_name'] = []
    return schema


def permission_create_schema():
    schema = {
        'id': [ignore],
        'content_type': [not_missing, not_empty, unicode, name_validator],
        'operation': [not_missing, not_empty, unicode, name_validator],
        'actions': [ignore_missing, list_of_strings, v.action_list_validator],
        '__after': [v.permission_unique_validator, ignore],
    }
    return schema


def permission_action_assign_schema():
    schema = {
        'content_type': [not_missing, not_empty, unicode],
        'operation': [not_missing, not_empty, unicode],
        'actions': [not_missing, not_empty, list_of_strings, v.action_list_validator],
    }
    return schema


def permission_action_unassign_schema():
    schema = {
        'content_type': [not_missing, not_empty, unicode],
        'operation': [not_missing, not_empty, unicode],
        'actions': [not_missing, not_empty, list_of_strings],
    }
    return schema
