# encoding: utf-8

from sqlalchemy import types, Table, Column, UniqueConstraint

from ckan.model import meta, types as _types, domain_object


permission_table = Table(
    'permission', meta.metadata,
    Column('id', types.UnicodeText, primary_key=True, default=_types.make_uuid),
    Column('content_type', types.UnicodeText, nullable=False),
    Column('operation', types.UnicodeText, nullable=False),
    UniqueConstraint('content_type', 'operation'),
)


class Permission(domain_object.DomainObject):

    @classmethod
    def get(cls, reference):
        """
        Returns a Permission object referenced by its id.
        """
        if not reference:
            return None

        return meta.Session.query(cls).get(reference)

    @classmethod
    def lookup(cls, content_type, operation):
        """
        Returns a Permission object by content type and operation.
        """
        return meta.Session.query(cls) \
            .filter_by(content_type=content_type, operation=operation) \
            .first()


meta.mapper(Permission, permission_table)
