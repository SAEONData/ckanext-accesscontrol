# encoding: utf-8

import logging
import json
import requests
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import OAuth2Error
from requests import RequestException

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckan.lib.redis import connect_to_redis
from ckanext.accesscontrol.openidconnect_config import config

log = logging.getLogger(__name__)


class OpenIDConnectError(Exception):
    pass


anyAuthException = (OpenIDConnectError, OAuth2Error, RequestException)


def identify():
    """
    Identify the user who is making the call to CKAN.
    """
    if getattr(tk.c, 'user', None):
        return  # user already identified

    log.debug("Identifying user")
    user_id = None
    user_data = None

    # API calls should arrive with an access token in the auth header
    auth_header = tk.request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = {'access_token': auth_header[7:]}
        try:
            _validate_token(token)
            user_id, user_data = _request_userinfo(token)
        except anyAuthException, e:
            log.error(str(e))
            return

    # if not an API call, we're dealing with a user logged in via the CKAN UI
    if not user_id:
        environ = tk.request.environ
        user_id = environ.get('repoze.who.identity', {}).get('repoze.who.userid')

    if user_id:
        user_dict = _persist_user(user_id, user_data)
        tk.c.user = user_dict['name']


def login():
    """
    Start the OpenID Connect authorization code flow; redirect the user to the
    auth server to authenticate.
    """
    log.debug("Login initiated")
    oauth2session = OAuth2Session(client_id=config.client_id, scope=config.scopes, redirect_uri=config.redirect_url)
    authorization_url, state = oauth2session.authorization_url(config.authorization_endpoint)
    _save_state(state)
    tk.redirect_to(authorization_url)


def callback():
    """
    Callback from the auth server after the user has logged in; the remainder of the
    authorization code flow and local login processing happens here.
    """
    log.debug("Callback from auth server")
    try:
        error = tk.request.params.get('error')
        if error:
            error_description = tk.request.params.get('error_description', '')
            raise OpenIDConnectError(_("Authorization server returned an error: %s %s") % (error, error_description))

        auth_code = tk.request.params['code']
        state = tk.request.params['state']
        _verify_state(state)

        oauth2session = OAuth2Session(client_id=config.client_id, redirect_uri=config.redirect_url)
        token = oauth2session.fetch_token(config.token_endpoint, client_secret=config.client_secret, code=auth_code)
        _validate_token(token)
        user_id, user_data = _request_userinfo(token)
        _save_token(user_id, token)
        _persist_user(user_id, user_data)
        _remember_login(user_id)

    except anyAuthException, e:
        log.error(str(e))
        tk.h.flash_error(str(e))

    tk.redirect_to(config.ckan_url)


def logout():
    """
    Perform a local logout then redirect to the auth server to logout there.
    """
    log.debug("Logout initiated")
    _forget_login()
    user_id = tk.c.userobj.id
    token = _load_token(user_id)
    id_token = token.get('id_token') if token else ''
    logout_url = config.endsession_endpoint + \
                 '?post_logout_redirect_uri=' + config.postlogout_redirect_url + \
                 '&id_token_hint=' + id_token
    tk.redirect_to(logout_url)


def logged_out():
    """
    Callback from the auth server after the user has been logged out.
    """
    log.debug("Post-logout callback from auth server")
    _forget_login()
    tk.redirect_to(config.ckan_url)


def _save_state(state):
    """
    Save a state string, used for verifying an OAuth2 login callback, to Redis,
    with an expiry time of 5 minutes.
    """
    redis = connect_to_redis()
    key = 'oidc_state:' + state
    redis.setex(key, '', 300)


def _verify_state(state):
    """
    Check that the state string provided with a callback matches one that was sent
    to the auth server.
    """
    redis = connect_to_redis()
    key = 'oidc_state:' + state
    if key not in redis:
        raise OpenIDConnectError(_("Invalid authorization state"))


def _save_token(user_id, token):
    """
    Save a user's auth token to Redis, with the expiry time specified within the token.
    """
    expiry_time = token.get('expires_in', 300)
    redis = connect_to_redis()
    key = 'oidc_token:' + user_id
    redis.setex(key, json.dumps(token), expiry_time)


def _load_token(user_id):
    """
    Retrieve a user's auth token from Redis.
    """
    redis = connect_to_redis()
    key = 'oidc_token:' + user_id
    token = redis.get(key) or '{}'
    token = json.loads(token)
    return token


def _validate_token(token):
    """
    Get detailed info about the access token from the auth server, and check that it is
    valid for our CKAN instance.
    :param token: token dictionary
    """
    access_token = token.get('access_token') if token else ''
    response = requests.post(config.introspection_endpoint, data={'token': access_token},
                             auth=(config.api_id, config.api_secret))
    response.raise_for_status()
    result = response.json()
    scopes = result.get('scope', '').split()
    client_id = result.get('client_id')
    valid = result.get('active') and \
            config.api_scope in scopes and \
            client_id in config.authorized_clients
    if not valid:
        raise OpenIDConnectError(_("Invalid access token"))


def _request_userinfo(token):
    """
    Get user info from the auth server.
    :param token: token dictionary
    :returns: tuple(user_id, user_data) where user_data is a dict of additional user values
    """
    oauth2session = OAuth2Session(token=token)
    response = oauth2session.get(config.userinfo_endpoint)
    response.raise_for_status()
    claims = response.json()
    user_id = claims.get(config.userid_field)
    user_data = {key: claims.get(key, '') for key in (config.username_field, config.email_field)}
    roles = claims.get(config.rolename_field) or []
    if isinstance(roles, basestring):
        roles = [roles]
    user_data[config.rolename_field] = roles
    return user_id, user_data


def _persist_user(user_id, user_data):
    """
    Create or update a user in the CKAN database, to correspond with the OpenID user info
    obtained from the authorization server. If user_data is not provided, simply return
    the user record if it exists.

    :param user_id: OpenID user id; becomes the CKAN user id
    :param user_data: dict of additional user info obtained from the auth server

    :returns: the CKAN user record
    :rtype: dictionary
    """
    user_data = user_data or {}
    roles = user_data.get(config.rolename_field, [])
    is_sysadmin = any((True for role in roles if config.is_sysadmin_role(role)))

    context = {
        'ignore_auth': True,
        'keep_email': True,
        'schema': {
            'id': [unicode],
            'name': [unicode],
            'email': [unicode],
            'sysadmin': [],
        },
    }
    data_dict = {
        'id': user_id,
        'name': user_data.get(config.username_field),
        'email': user_data.get(config.email_field),
        'sysadmin': is_sysadmin,
    }
    try:
        user_dict = tk.get_action('user_show')(context, {'id': user_id})

        if user_data:
            update = False
            for key, value in data_dict.iteritems():
                if user_dict.get(key) != value:
                    update = True
                    break
            if update:
                user_dict = tk.get_action('user_update')(context, data_dict)
                log.info("Updated user record for OpenID user %s (%s)", user_id, user_dict['name'])

    except tk.ObjectNotFound:
        if not user_data:
            raise
        user_dict = tk.get_action('user_create')(context, data_dict)
        log.info("Created user record for OpenID user %s (%s)", user_id, user_dict['name'])

    return user_dict


def _remember_login(user_id):
    """
    Tell repoze.who about our user; this creates a user id cookie.
    """
    environ = tk.request.environ
    plugins = environ.get('repoze.who.plugins', {})
    rememberer = plugins['auth_tkt']
    identity = {'repoze.who.userid': user_id}
    headers = rememberer.remember(environ, identity)
    for header, value in headers:
        tk.response.headers.add(header, value)


def _forget_login():
    """
    Tell repoze.who that we've logged out; this deletes the user id cookie.
    """
    environ = tk.request.environ
    plugins = environ.get('repoze.who.plugins', {})
    rememberer = plugins['auth_tkt']
    headers = rememberer.forget(environ, None)
    for header, value in headers:
        tk.response.headers.add(header, value)
