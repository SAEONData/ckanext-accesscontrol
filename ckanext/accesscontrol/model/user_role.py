# encoding: utf-8

from sqlalchemy import types, Table, Column, ForeignKey, UniqueConstraint
import vdm.sqlalchemy

from ckan.model import meta, core, types as _types, domain_object


user_role_table = Table(
    'user_role', meta.metadata,
    Column('id', types.UnicodeText, primary_key=True, default=_types.make_uuid),
    Column('user_id', types.UnicodeText, ForeignKey('user.id'), nullable=False),
    Column('role_id', types.UnicodeText, ForeignKey('role.id'), nullable=False),
    UniqueConstraint('user_id', 'role_id'),
)

vdm.sqlalchemy.make_table_stateful(user_role_table)
user_role_revision_table = core.make_revisioned_table(user_role_table)


class UserRole(vdm.sqlalchemy.RevisionedObjectMixin,
               vdm.sqlalchemy.StatefulObjectMixin,
               domain_object.DomainObject):

    @classmethod
    def get(cls, reference):
        """
        Returns a UserRole object referenced by its id.
        """
        if not reference:
            return None

        return meta.Session.query(cls).get(reference)

    @classmethod
    def lookup(cls, user_id, role_id):
        """
        Returns a UserRole object by user id and role id.
        """
        return meta.Session.query(cls) \
            .filter_by(user_id=user_id, role_id=role_id) \
            .first()


meta.mapper(UserRole, user_role_table,
            extension=[vdm.sqlalchemy.Revisioner(user_role_revision_table)])

vdm.sqlalchemy.modify_base_object_mapper(UserRole, core.Revision, core.State)
UserRoleRevision = vdm.sqlalchemy.create_object_version(
    meta.mapper, UserRole, user_role_revision_table)
