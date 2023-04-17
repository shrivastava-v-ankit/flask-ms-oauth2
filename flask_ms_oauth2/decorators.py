#!/usr/bin/env python3

"""
File handle the decorators for Microsoft OAuth2 login / logout features.
"""

import logging
import json
import requests
import base64
from requests.auth import HTTPBasicAuth
from functools import wraps
from flask import redirect
from flask import request
import jwt
from flask import session
from flask import url_for
import msal
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from .config import Config

logger = logging.getLogger(__name__)
config = Config()


def login_handler(fn):
    """
    A decorator to redirect users to Microsoft OAuth2 login if they aren't already.
    If already logged in user will redirect redirect uri.
    Use this decorator on the login endpoint.
    This handle will not return to handle the respose rather redirect to
    redirect uri.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_url = build_ms_oauth2_url(authority=config.authority,
                                       scopes=config.scopes,
                                       state=config.state,
                                       client_id=config.client_id,
                                       client_secret=config.client_secret,
                                       redirect_uri=config.redirect_uri)

        res = redirect(auth_url)
        logger.info(
            "Got Microsoft OAuth2 Login, redirecting to Microsoft OAuth2 for Auth")
        return res
    return wrapper


def build_ms_oauth2_app(authority, client_id, client_secret):
    msml_app = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_secret)
    return msml_app


def build_ms_oauth2_url(authority,
                        scopes,
                        state,
                        client_id,
                        client_secret,
                        redirect_uri):
    msml_app = build_ms_oauth2_app(authority=authority,
                                   client_id=client_id,
                                   client_secret=client_secret)
    req_url = msml_app.get_authorization_request_url(
        scopes=scopes,
        state=state,
        redirect_uri=redirect_uri)
    return req_url


def callback_handler(fn):
    """
    A decorator to handle redirects from Microsoft OAuth2 login and signup. It
    handles and verifies and exchangs the code for tokens.
    This decorator also pushes the basic informations in Flask session.
    Basic informations are:
        * username
        * id
        * email
        * expires
        * refresh_token
        * access_token
        * All SAML assertions.
    Use this decorator on the redirect endpoint on your application.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_success = False
        logger.info("Login is successfull from Microsoft OAuth2.")

        csrf_token = config.state
        csrf_state = None

        if csrf_token:
            csrf_state = request.args.get('state')

        if csrf_token == csrf_state:
            if "error" not in request.args:
                logger.info(
                    "Authenticating Microsoft OAuth2 with code exchange.")
                if request.args.get('code'):
                    response = build_ms_oauth2_app(authority=config.authority,
                                                   client_id=config.client_id,
                                                   client_secret=config.client_secret).acquire_token_by_authorization_code(request.args['code'],
                                                                                                                           scopes=config.scopes,
                                                                                                                           redirect_uri=config.redirect_uri)

                    if "error" not in response:
                        auth_success = True
                        logger.info("Login is success for code exchange.")
                        logger.info("Decode the access token from response.")

                        id_token = verify(response.get("access_token"))
                        username = None
                        email = None
                        provider_type = "msoauth2"

                        if not username:
                            username = id_token["name"]
                        if not email and 'upn' in id_token:
                            email = id_token["upn"]

                        saml_assertions = []
                        for token, val in id_token.items():
                            if token not in config.skip_tokens:
                                token_vals = val.replace("[", "")
                                token_vals = token_vals.replace("]", "")
                                token_vals = token_vals.split(",")
                                vals = []
                                for token_val in token_vals:
                                    vals.append(token_val.strip())
                                saml_assertions.append({token: vals})

                        update_session(username=username,
                                       id=id_token["oid"],
                                       email=email,
                                       expires=id_token["exp"],
                                       refresh_token=response.get(
                                           "refresh_token"),
                                       access_token=response.get(
                                           "access_token"),
                                       provider_type=provider_type,
                                       saml_assertions=saml_assertions)
        if not auth_success:
            error_uri = config.redirect_error_uri
            if error_uri:
                resp = redirect(url_for(error_uri))
                return resp
            else:
                msg = f"Something went wrong during authentication"
                return json.dumps({'Error': msg}), 500
        return fn(*args, **kwargs)
    return wrapper


def update_session(username: str,
                   id,
                   email: str,
                   expires,
                   refresh_token,
                   access_token,
                   provider_type,
                   saml_assertions):
    """
    Method to update the Flask Session object with the informations after
    successfull login.
    :param username (str):          Authenticated user.
    :param id (str):                ID of authenticated user.
                                    user is subscribed.
    :param email (str):             Email id of authenticated user.
    :param expires (str):           JWT session timeout.
    :param refresh_token (str):     JWT refresh token received in respose.
    :param access_token (str):      JWT access token received in respose.
    :param provider_type (str):     Default is "msoauth2".
    :param saml_assertions (list):  List of all SAML assertions.
    """
    session['username'] = username
    session['id'] = id
    session['email'] = email
    session['expires'] = expires
    session['refresh_token'] = refresh_token
    session['access_token'] = access_token
    session['provider_type'] = provider_type
    session['saml_assertions'] = saml_assertions
    session.modified = True


def ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key


def decode_value(val):
    decoded = base64.urlsafe_b64decode(ensure_bytes(val) + b'==')
    return int.from_bytes(decoded, 'big')


def rsa_pem_from_jwk(jwk):
    return RSAPublicNumbers(n=decode_value(jwk['n']),
                            e=decode_value(jwk['e'])
                            ).public_key(default_backend()).public_bytes(encoding=serialization.Encoding.PEM,
                                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                                         )


def get_public_key(jwk):
    return rsa_pem_from_jwk(jwk)


def verify(token: str):
    """
    Verifies a JWT string's signature and validates reserved claims.
    Get the key id from the header, locate it in the Microsoft OAuth2 keys and verify
    the key
    :param token (str):         A signed JWS to be verified.
    :param access_token (str):  An access token string. If the "at_hash" claim
                                is included in the
    :return id_token (dict):    The dict representation of the claims set,
                                assuming the signature is valid and all
                                requested data validation passes.
    """
    header = jwt.get_unverified_header(token)
    key = [k for k in config.get_jwt_key if k["kid"] == header['kid']][0]

    if "issuer" not in key:
        issuer = f"{config.authority}/v2.0"
    else:
        issuer = key["issuer"].replace('{tenantid}', config.tenant_id)
    decoded = jwt.decode(jwt=token,
                         key=get_public_key(key),
                         verify=False,
                         options={"verify_signature": False},
                         algorithms=['RS256'],
                         audience=[config.client_id],
                         issuer=issuer)
    return decoded


def logout_handler(fn):
    """
    A decorator to logout from Microsoft OAuth2 and return to signout uri.
    Use this decorator on the Microsoft OAuth2 logout endpoint.
    This handle will not return to handle any respose rather redirect to
    signout uri.
    This decorator also clears the basic informations from Flask session.
    Basic informations are:
        * username
        * id
        * email
        * expires
        * refresh_token
        * access_token
        * provider_type
        * saml_assertions
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        update_session(username=None,
                       id=None,
                       email=None,
                       expires=None,
                       refresh_token=None,
                       access_token=None,
                       provider_type=None,
                       saml_assertions=[])
        logger.info(
            "Microsoft OAuth2 Logout, redirecting to Microsoft OAuth2 for logout and terminating sessions")

        res = redirect(config.logout_uri)
        return res
    return wrapper
