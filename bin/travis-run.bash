#!/bin/bash
set -e

nosetests --ckan \
          --nologcapture \
          --with-pylons=subdir/test.ini \
          --with-coverage \
          --cover-package=ckanext.openidconnect \
          --cover-inclusive \
          --cover-erase \
          --cover-tests \
          ckanext/openidconnect/tests
