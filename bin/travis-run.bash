#!/bin/bash
set -e

nosetests --ckan \
          --nologcapture \
          --with-pylons=subdir/test.ini \
          --with-coverage \
          --cover-package=ckanext.accesscontrol \
          --cover-inclusive \
          --cover-erase \
          --cover-tests \
          ckanext/accesscontrol/tests
