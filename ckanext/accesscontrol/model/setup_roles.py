# encoding: utf-8

import logging

from ckanext.accesscontrol.model import *

log = logging.getLogger(__name__)


def init_tables():
    tables = (
        role_table,
        role_revision_table,
        permission_table,
        permission_action_table,
        role_permission_table,
        role_permission_revision_table,
        user_role_table,
        user_role_revision_table,
    )
    for table in tables:
        if not table.exists():
            log.debug("Creating table %s", table.name)
            table.create()
        else:
            log.debug("Table %s already exists", table.name)
