# ckanext-openidconnect

[![Travis CI](https://travis-ci.org/SAEONData/ckanext-openidconnect.svg?branch=master)](https://travis-ci.org/SAEONData/ckanext-openidconnect)
[![Coverage](https://coveralls.io/repos/SAEONData/ckanext-openidconnect/badge.svg)](https://coveralls.io/r/SAEONData/ckanext-openidconnect)

An extension for [CKAN](https://ckan.org) enabling authentication via an
OpenID Connect provider.

## Requirements

This extension has been developed and tested with CKAN version 2.7.4.

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

The following configuration options are available for _ckanext-openidconnect_:

    ckan.openidconnect.userinfo_endpoint = <url>

e.g.

    ckan.openidconnect.userinfo_endpoint = https://your.auth.server.com/connect/userinfo

An additional option `ckan.openidconnect.insecure_transport` (boolean, default `False`)
may be set to `True` for local development or automated tests to permit insecure communications
with an authorization server. Never set this option in production!

Restart your CKAN instance after any configuration changes.
