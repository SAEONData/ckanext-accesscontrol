# ckanext-openidconnect

[![Travis CI](https://travis-ci.org/SAEONData/ckanext-openidconnect.svg?branch=master)](https://travis-ci.org/SAEONData/ckanext-openidconnect)
[![Coverage](https://coveralls.io/repos/SAEONData/ckanext-openidconnect/badge.svg)](https://coveralls.io/r/SAEONData/ckanext-openidconnect)

An extension for [CKAN](https://ckan.org) enabling authentication and authorization via an
OpenID Connect provider.

## Requirements

This extension has been developed and tested with CKAN version 2.8.2.

Redis is required for maintaining login state information.

## Installation

Activate your CKAN virtual environment:

    . /usr/lib/ckan/default/bin/activate

Install the latest development version of _ckanext-openidconnect_ and its dependencies:

    cd /usr/lib/ckan/default
    pip install -e 'git+https://github.com/SAEONData/ckanext-openidconnect.git#egg=ckanext-openidconnect'
    pip install -r src/ckanext-openidconnect/requirements.txt

In a production environment, you'll probably want to pin a specific
[release version](https://github.com/SAEONData/ckanext-openidconnect/releases) instead, e.g.:

    pip install -e 'git+https://github.com/SAEONData/ckanext-openidconnect.git@v1.0.0#egg=ckanext-openidconnect'

Open your CKAN configuration file (e.g. `/etc/ckan/default/production.ini`) and
add `openidconnect` to the list of plugins :

    ckan.plugins = ... openidconnect

Restart your CKAN instance.

## Configuration

The following configuration options are available for _ckanext-openidconnect_.
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
| ckan.openidconnect.authorized_clients     | | Space-separated list of client IDs that are allowed to access the CKAN instance. This should include the client_id specified above.
| ckan.openidconnect.register_url           | | Auth service URL for new user registration.
| ckan.openidconnect.reset_url              | | Auth service URL for resetting a password.
| ckan.openidconnect.edit_url               | | Auth service URL for editing a user profile.
| ckan.openidconnect.userid_field           | sub   | The user id field in the ID token.
| ckan.openidconnect.username_field         | name  | The user name field in the ID token.
| ckan.openidconnect.email_field            | email | The email address field in the ID token.
| ckan.openidconnect.rolename_field         | role  | The role name field in the ID token.
| ckan.openidconnect.sysadmin_role          | sysadmin | The sysadmin role name.
| ckan.openidconnect.insecure_transport     | False | Set to True for development / testing to permit insecure communication with an auth server. Never set this option in production!

Restart your CKAN instance after any configuration changes.
