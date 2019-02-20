# encoding: utf-8

import ckan.plugins.toolkit as tk
from ckanext.accesscontrol.logic import validators as v

not_empty = tk.get_validator('not_empty')
not_missing = tk.get_validator('not_missing')
ignore = tk.get_validator('ignore')
ignore_missing = tk.get_validator('ignore_missing')
name_validator = tk.get_validator('name_validator')


def role_create_schema():
    schema = {
        'id': [ignore],
        'name': [not_missing, not_empty, unicode, name_validator, v.role_name_validator],
        'title': [ignore_missing, unicode],
        'description': [ignore_missing, unicode],
    }
    return schema


def role_show_schema():
    schema = dict.fromkeys(role_create_schema(), [])
    schema['revision_id'] = []
    return schema
