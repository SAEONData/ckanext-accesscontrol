# encoding: utf-8

from sqlalchemy import types, Table, Column, ForeignKey, UniqueConstraint

from ckan.model import meta, types as _types, domain_object


permission_action_table = Table(
    'permission_action', meta.metadata,
    Column('id', types.UnicodeText, primary_key=True, default=_types.make_uuid),
    Column('permission_id', types.UnicodeText, ForeignKey('permission.id'), nullable=False),
    Column('action_name', types.UnicodeText, nullable=False),
    UniqueConstraint('permission_id', 'action_name'),
)


class PermissionAction(domain_object.DomainObject):
    pass


meta.mapper(PermissionAction, permission_action_table)
