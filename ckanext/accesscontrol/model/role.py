# encoding: utf-8

from sqlalchemy import types, Table, Column
import vdm.sqlalchemy

from ckan.model import meta, core, types as _types, domain_object


role_table = Table(
    'role', meta.metadata,
    Column('id', types.UnicodeText, primary_key=True, default=_types.make_uuid),
    Column('name', types.UnicodeText, nullable=False, unique=True),
    Column('title', types.UnicodeText),
    Column('description', types.UnicodeText),
)

vdm.sqlalchemy.make_table_stateful(role_table)
role_revision_table = core.make_revisioned_table(role_table)


class Role(vdm.sqlalchemy.RevisionedObjectMixin,
           vdm.sqlalchemy.StatefulObjectMixin,
           domain_object.DomainObject):

    @classmethod
    def get(cls, reference):
        """
        Returns a Role object referenced by its id or name.
        """
        if not reference:
            return None

        role = meta.Session.query(cls).get(reference)
        if role is None:
            role = cls.by_name(reference)
        return role


meta.mapper(Role, role_table,
            extension=[vdm.sqlalchemy.Revisioner(role_revision_table)])

vdm.sqlalchemy.modify_base_object_mapper(Role, core.Revision, core.State)
RoleRevision = vdm.sqlalchemy.create_object_version(
    meta.mapper, Role, role_revision_table)
