# encoding: utf-8

from sqlalchemy import types, Table, Column, UniqueConstraint, ForeignKey
import vdm.sqlalchemy

from ckan.model import meta, core, types as _types, domain_object


role_permission_table = Table(
    'role_permission', meta.metadata,
    Column('id', types.UnicodeText, primary_key=True, default=_types.make_uuid),
    Column('role_id', types.UnicodeText, ForeignKey('role.id'), nullable=False),
    Column('content_type', types.UnicodeText, nullable=False),
    Column('operation', types.UnicodeText, nullable=False),
    UniqueConstraint('role_id', 'content_type', 'operation'),
)

vdm.sqlalchemy.make_table_stateful(role_permission_table)
role_permission_revision_table = core.make_revisioned_table(role_permission_table)


class RolePermission(vdm.sqlalchemy.RevisionedObjectMixin,
                     vdm.sqlalchemy.StatefulObjectMixin,
                     domain_object.DomainObject):

    @classmethod
    def get(cls, reference):
        """
        Returns a RolePermission object referenced by its id.
        """
        if not reference:
            return None

        return meta.Session.query(cls).get(reference)

    @classmethod
    def lookup(cls, role_id, content_type, operation):
        """
        Returns a RolePermission object by role and permission.
        """
        return meta.Session.query(cls) \
            .filter_by(role_id=role_id, content_type=content_type, operation=operation) \
            .first()


meta.mapper(RolePermission, role_permission_table,
            extension=[vdm.sqlalchemy.Revisioner(role_permission_revision_table)])

vdm.sqlalchemy.modify_base_object_mapper(RolePermission, core.Revision, core.State)
RolePermissionRevision = vdm.sqlalchemy.create_object_version(
    meta.mapper, RolePermission, role_permission_revision_table)
