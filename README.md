# ckanext-accesscontrol

[![Travis CI](https://travis-ci.org/SAEONData/ckanext-accesscontrol.svg?branch=master)](https://travis-ci.org/SAEONData/ckanext-accesscontrol)
[![Coverage](https://coveralls.io/repos/SAEONData/ckanext-accesscontrol/badge.svg)](https://coveralls.io/r/SAEONData/ckanext-accesscontrol)

An extension for [CKAN](https://ckan.org) providing OpenID connect authentication
and role-based access control.

## Requirements

This extension has been developed and tested with CKAN version 2.8.2.

Redis is required for maintaining login state information.

## Installation

Activate your CKAN virtual environment:

    . /usr/lib/ckan/default/bin/activate

Install the latest development version of _ckanext-accesscontrol_ and its dependencies:

    cd /usr/lib/ckan/default
    pip install -e 'git+https://github.com/SAEONData/ckanext-accesscontrol.git#egg=ckanext-accesscontrol'
    pip install -r src/ckanext-accesscontrol/requirements.txt

In a production environment, you'll probably want to pin a specific
[release version](https://github.com/SAEONData/ckanext-accesscontrol/releases) instead, e.g.:

    pip install -e 'git+https://github.com/SAEONData/ckanext-accesscontrol.git@v1.0.0#egg=ckanext-accesscontrol'

Create the database tables for the _roles_ plugin, if required:

    cd /usr/lib/ckan/default/src/ckanext-accesscontrol
    paster roles initdb -c /etc/ckan/default/development.ini

Add `roles` and/or `openidconnect`, as required, to the list of plugins in your CKAN configuration file
(e.g. `/etc/ckan/default/production.ini`):

    ckan.plugins = ... roles openidconnect

Restart your CKAN instance.

## Configuration

The following options are applicable to the _openidconnect_ plugin.
Where a default is not defined, a value **must** be set in the configuration file.

| Option | Default | Description |
| ------ | ------- | ----------- |
| ckan.openidconnect.authorization_endpoint | | Auth service authorization endpoint (URL).
| ckan.openidconnect.token_endpoint         | | Auth service token endpoint (URL).
| ckan.openidconnect.endsession_endpoint    | | Auth service logout endpoint (URL).
| ckan.openidconnect.introspection_endpoint | | Auth service token introspection endpoint (URL).
| ckan.openidconnect.userinfo_endpoint      | | Auth service user info endpoint (URL).
| ckan.openidconnect.client_id              | | The ID of the client resource that represents the CKAN UI in the auth service.
| ckan.openidconnect.client_secret          | | The client secret specified for the above client resource.
| ckan.openidconnect.api_scope              | | The scope associated with the API resource that represents the CKAN instance in the auth service.
| ckan.openidconnect.api_id                 | | The ID of the above API resource.
| ckan.openidconnect.api_secret             | | The secret specified for the above API resource.
| ckan.openidconnect.edit_url               | | Auth service URL for editing a user profile.
| ckan.openidconnect.insecure_transport     | False | Set to True in a dev environment to permit insecure communication with the auth server. Never set this option in production!
| ckan.openidconnect.no_verify_ssl_cert     | False | Set to True in a dev environment to not verify the SSL certificate of the auth server. Never set this option in production!

Restart your CKAN instance after any configuration changes.
