# encoding: utf-8

import logging

from ckanext.accesscontrol.model.role import *
from ckanext.accesscontrol.model.role_permission import *
from ckanext.accesscontrol.model.user_role import *

log = logging.getLogger(__name__)


def init_tables():
    tables = (
        role_table,
        role_revision_table,
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
