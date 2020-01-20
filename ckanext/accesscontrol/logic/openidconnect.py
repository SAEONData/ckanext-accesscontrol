# encoding: utf-8

import logging
import json
import requests
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import OAuth2Error
from requests import RequestException
from sqlalchemy.sql import select

import ckan.plugins.toolkit as tk
from ckan.common import _
from ckan.lib.redis import connect_to_redis
from ckanext.accesscontrol.config import config
import ckan.model as model
from ckanext.accesscontrol.model.user_role import user_role_table
from ckanext.accesscontrol.model.role import role_table

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

    # initialize this to something, because CKAN's user_create (which we call from _save_objects)
    # reads context['user']; CKAN does this automatically for UI requests, but not for API calls
    tk.c.user = ''

    log.debug("Identifying user")

    # API calls should arrive with an access token in the auth header
    auth_header = tk.request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = {'access_token': auth_header[7:]}
        try:
            token_data = _extract_token_data(token)
            _save_objects(token_data)
            tk.c.user = token_data['email']
        except anyAuthException, e:
            log.error(str(e))
        return

    # if not an API call, we're dealing with a user logged in via the CKAN UI
    environ = tk.request.environ
    user_id = environ.get('repoze.who.identity', {}).get('repoze.who.userid')
    if user_id:
        user_dict = tk.get_action('user_show')({'ignore_auth': True}, {'id': user_id})
        tk.c.user = user_dict['name']


def login():
    """
    Start the OpenID Connect authorization code flow; redirect the user to the
    auth server to authenticate.
    """
    log.debug("Login initiated")
    oauth2session = OAuth2Session(client_id=config.client_id, scope=config.scopes, redirect_uri=config.redirect_url)
    authorization_url, state = oauth2session.authorization_url(config.authorization_endpoint, mode='login')
    _save_state(state)
    tk.redirect_to(authorization_url)


def register():
    """
    The process is identical to a login, from CKAN's perspective. Once signup is complete, the user
    will be authenticated and we'll get an OAuth2 callback.
    """
    log.debug("Signup initiated")
    oauth2session = OAuth2Session(client_id=config.client_id, scope=config.scopes, redirect_uri=config.redirect_url)
    authorization_url, state = oauth2session.authorization_url(config.authorization_endpoint, mode='signup')
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
        token = oauth2session.fetch_token(config.token_endpoint, client_secret=config.client_secret, code=auth_code,
                                          verify=not config.no_verify_ssl_cert)
        token_data = _extract_token_data(token)
        user_id = token_data['user_id']
        _save_token(user_id, token)
        _save_objects(token_data)
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
    user_id = tk.c.userobj.id if tk.c.userobj else None
    token = _load_token(user_id)
    id_token = token.get('id_token') if token else ''
    if id_token:
        logout_url = config.endsession_endpoint + \
                     '?post_logout_redirect_uri=' + config.postlogout_redirect_url + \
                     '&id_token_hint=' + id_token
        tk.redirect_to(logout_url)
    else:
        # if we don't have an id token then we cannot logout from the auth server; so just do a local logout
        tk.redirect_to(config.ckan_url)


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
    if not user_id:
        return {}
    redis = connect_to_redis()
    key = 'oidc_token:' + user_id
    token = redis.get(key) or '{}'
    token = json.loads(token)
    return token


def _extract_token_data(token):
    """
    Validate the token and get access and user info from the auth server.

    Note: This is integrated specifically with the ODP Identity Service in terms
    of data that is expected to be provided on the access and ID tokens.

    :param token: the received encoded token dict
    :returns: dict with decoded token data, as follows::
        {
            'user_id'
            'email'
            'firstname'
            'lastname'
            'superuser'
            'privileges': [{
                'institution'
                'institution_name'
                'role'
                'role_name'
            }]
        }
    """
    # get access token data from the introspection endpoint
    access_token = token.get('access_token') if token else ''
    response = requests.post(config.introspection_endpoint, data={'token': access_token},
                             auth=(config.api_id, config.api_secret), verify=not config.no_verify_ssl_cert)
    response.raise_for_status()
    access_token_data = response.json()
    scopes = access_token_data.get('scope', '').split()
    valid = access_token_data.get('active') and config.api_scope in scopes
    if not valid:
        raise OpenIDConnectError(_("Invalid access token"))

    # get id token data from the userinfo endpoint
    oauth2session = OAuth2Session(token=token)
    response = oauth2session.get(config.userinfo_endpoint, verify=not config.no_verify_ssl_cert)
    response.raise_for_status()
    id_token_data = response.json()

    user_id = access_token_data.get('sub')
    email = id_token_data.get('email')
    firstname = id_token_data.get('firstname', '')
    lastname = id_token_data.get('lastname', '')
    if not user_id or not email:
        raise OpenIDConnectError(_("Invalid access token"))

    superuser = access_token_data.get('ext', {}).get('superuser', False)
    if type(superuser) is not bool:
        raise OpenIDConnectError(_("Invalid access token"))

    privileges = []
    for privilege in access_token_data.get('ext', {}).get('privileges', []):
        if privilege.get('scope') == config.api_scope:
            institution = privilege.get('institution')
            institution_name = privilege.get('institution_name', institution)
            role = privilege.get('role')
            role_name = privilege.get('role_name', role)
            if not institution or not role:
                raise OpenIDConnectError(_("Invalid access token"))
            privileges += [{
                'institution': institution,
                'institution_name': institution_name,
                'role': role,
                'role_name': role_name,
            }]

    return {
        'user_id': user_id,
        'email': email,
        'firstname': firstname,
        'lastname': lastname,
        'superuser': superuser,
        'privileges': privileges,
    }


def _save_objects(token_data):
    """
    Create or update CKAN models.
    """
    _save_user(token_data)
    _save_organizations(token_data)
    _save_roles(token_data)
    _save_privileges(token_data)


def _save_user(token_data):
    """
    Create or update the CKAN user represented by the token.
    """
    context = {
        'ignore_auth': True,
        'keep_email': True,
        'schema': {
            'id': [unicode],
            'name': [unicode],
            'email': [unicode],
            'fullname': [unicode],
            'sysadmin': [],
        },
    }
    data_dict = {
        'id': token_data['user_id'],
        'name': token_data['email'],
        'email': token_data['email'],
        'fullname': token_data['firstname'] + ' ' + token_data['lastname'],
        'sysadmin': token_data['superuser'],
    }
    try:
        user_dict = tk.get_action('user_show')(context, {'id': data_dict['id']})
        update = False
        for key, value in data_dict.iteritems():
            if user_dict.get(key) != value:
                update = True
                break
        if update:
            user_dict = tk.get_action('user_update')(context, data_dict)
            log.info("Updated user record for %s (%s)", user_dict['id'], user_dict['name'])

    except tk.ObjectNotFound:
        user_dict = tk.get_action('user_create')(context, data_dict)
        log.info("Created user record for %s (%s)", user_dict['id'], user_dict['name'])


def _save_organizations(token_data):
    """
    Create or update any organizations referenced in the token privileges.
    """
    # make the 'default' sysadmin user the admin of any created organizations
    # note: we use a new context for each action call to avoid CKAN confusion
    for privilege in token_data['privileges']:
        org_name = privilege['institution']
        org_title = privilege['institution_name']
        try:
            org_dict = tk.get_action('organization_show')({'ignore_auth': True}, {'id': org_name})
            if org_dict['title'] != org_title:
                org_dict['title'] = org_title
                tk.get_action('organization_update')({'ignore_auth': True, 'user': 'default'}, org_dict)
        except tk.ObjectNotFound:
            tk.get_action('organization_create')({'ignore_auth': True, 'user': 'default'},
                                                 {'name': org_name, 'title': org_title})


def _save_roles(token_data):
    """
    Create or update any roles referenced in the token privileges.
    """
    try:
        role_show = tk.get_action('role_show')
        role_create = tk.get_action('role_create')
        role_update = tk.get_action('role_update')
    except:
        return  # roles plugin is not enabled

    # note: we use a new context for each action call to avoid CKAN confusion
    for privilege in token_data['privileges']:
        role_name = privilege['role']
        role_title = privilege['role_name']
        try:
            role_dict = role_show({'ignore_auth': True}, {'id': role_name})
            if role_dict['title'] != role_title:
                role_dict['title'] = role_title
                role_update({'ignore_auth': True}, role_dict)
        except tk.ObjectNotFound:
            role_create({'ignore_auth': True}, {'name': role_name, 'title': role_title})


def _save_privileges(token_data):
    """
    Synchronize the CKAN user's role assignments with those specified in the token.
    """
    try:
        user_role_assign = tk.get_action('user_role_assign')
        user_role_unassign = tk.get_action('user_role_unassign')
    except:
        return  # roles plugin is not enabled

    session = model.Session
    user_id = token_data['user_id']

    requested_roles = set()
    for privilege in token_data['privileges']:
        requested_roles |= {(privilege['role'], privilege['institution'])}

    assigned_roles = set()
    org_table = model.group.group_table
    q = select([role_table.c.name, org_table.c.name],
               from_obj=user_role_table
               .join(role_table, user_role_table.c.role_id == role_table.c.id)
               .join(org_table, user_role_table.c.organization_id == org_table.c.id)) \
        .where(user_role_table.c.user_id == user_id) \
        .where(user_role_table.c.state == 'active') \
        .where(role_table.c.state == 'active') \
        .where(org_table.c.state == 'active')
    results = session.execute(q)
    for result in results:
        assigned_roles |= {(result[0], result[1])}

    roles_to_assign = requested_roles - assigned_roles
    roles_to_unassign = assigned_roles - requested_roles

    # note: we use a new context for each action call to avoid CKAN confusion
    for role_to_assign in roles_to_assign:
        try:
            user_role_assign({'ignore_auth': True}, {
                'user_id': user_id,
                'role_id': role_to_assign[0],
                'organization_id': role_to_assign[1],
            })
        except tk.ObjectNotFound:
            # one of the objects involved has been deleted in CKAN; ignore and continue
            pass

    # note: we use a new context for each action call to avoid CKAN confusion
    for role_to_unassign in roles_to_unassign:
        try:
            user_role_unassign({'ignore_auth': True}, {
                'user_id': user_id,
                'role_id': role_to_unassign[0],
                'organization_id': role_to_unassign[1],
            })
        except tk.ObjectNotFound:
            # one of the objects involved has been deleted in CKAN; ignore and continue
            pass


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
