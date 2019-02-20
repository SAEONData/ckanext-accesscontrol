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

Create the required database tables:

    cd /usr/lib/ckan/default/src/ckanext-accesscontrol
    paster accesscontrol initdb -c /etc/ckan/default/development.ini

Add `accesscontrol` to the list of plugins in your CKAN configuration file (e.g. `/etc/ckan/default/production.ini`):

    ckan.plugins = ... accesscontrol

Restart your CKAN instance.

## Configuration

The following configuration options are available for _ckanext-accesscontrol_.
Where a default is not defined, a value **must** be set in the configuration file.

| Option | Default | Description |
| ------ | ------- | ----------- |
| ckan.accesscontrol.authorization_endpoint | | Auth service authorization endpoint (URL).
| ckan.accesscontrol.token_endpoint         | | Auth service token endpoint (URL).
| ckan.accesscontrol.endsession_endpoint    | | Auth service logout endpoint (URL).
| ckan.accesscontrol.introspection_endpoint | | Auth service token introspection endpoint (URL).
| ckan.accesscontrol.userinfo_endpoint      | | Auth service user info endpoint (URL).
| ckan.accesscontrol.client_id              | | The ID of the client resource that represents the CKAN UI in the auth service.
| ckan.accesscontrol.client_secret          | | The client secret specified for the above client resource.
| ckan.accesscontrol.api_scope              | | The scope associated with the API resource that represents the CKAN instance in the auth service.
| ckan.accesscontrol.api_id                 | | The ID of the above API resource.
| ckan.accesscontrol.api_secret             | | The secret specified for the above API resource.
| ckan.accesscontrol.authorized_clients     | | Space-separated list of client IDs that are allowed to access the CKAN instance. This should include the client_id specified above.
| ckan.accesscontrol.register_url           | | Auth service URL for new user registration.
| ckan.accesscontrol.reset_url              | | Auth service URL for resetting a password.
| ckan.accesscontrol.edit_url               | | Auth service URL for editing a user profile.
| ckan.accesscontrol.userid_field           | sub   | The user id field in the ID token.
| ckan.accesscontrol.username_field         | name  | The user name field in the ID token.
| ckan.accesscontrol.email_field            | email | The email address field in the ID token.
| ckan.accesscontrol.rolename_field         | role  | The role name field in the ID token.
| ckan.accesscontrol.sysadmin_role          | sysadmin | The sysadmin role name.
| ckan.accesscontrol.insecure_transport     | False | Set to True for development / testing to permit insecure communication with an auth server. Never set this option in production!

Restart your CKAN instance after any configuration changes.
