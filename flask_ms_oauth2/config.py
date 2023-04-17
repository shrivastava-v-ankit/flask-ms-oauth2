#!/usr/bin/env python3

"""
File to handle the configurations.
"""

import os
import logging
from flask import current_app
import requests

logger = logging.getLogger(__name__)


class Config(object):
    """
    Helper class to hold the configurations and is meant for internal use
    by module only. This is a loose wrapper for flasks application config
    (alias: `app.config`).
    """

    @property
    def get_auth_manager(self):
        auth_manager = current_app.extensions.get("flask-ms-oauth2")
        if not auth_manager:
            msg = "Microsoft OAuth2 extention is not registerd with Flask application."
            logger.info(msg)
            raise RuntimeError(msg)

        return auth_manager

    def get_config_value(self, key, error_message, is_key_required, is_value_required):
        if key not in current_app.config and is_key_required:
            raise RuntimeError(error_message)

        value = None
        if key in current_app.config:
            value = current_app.config[key]

        if is_value_required and not value:
            raise RuntimeError(error_message)
        return value

    @property
    def client_id(self):
        error_message = 'CLIENT_ID must be set to validate the audience claim.'
        client_id = self.get_config_value(key="CLIENT_ID",
                                          error_message=error_message,
                                          is_key_required=True,
                                          is_value_required=True)
        return client_id

    @property
    def client_secret(self):
        error_message = 'CLIENT_SECRET must be set to validate the audience claim.'
        client_secret = self.get_config_value(key="CLIENT_SECRET",
                                              error_message=error_message,
                                              is_key_required=True,
                                              is_value_required=True)
        return client_secret

    @property
    def tenant_id(self):
        error_message = 'TENANT_ID must be specified to locate the authority.'
        tenant_id = self.get_config_value(key="TENANT_ID",
                                          error_message=error_message,
                                          is_key_required=True,
                                          is_value_required=True)
        return tenant_id

    @property
    def redirect_uri(self):
        error_message = 'REDIRECT_URI must be set to obtain callback url.'
        uri = self.get_config_value(key="REDIRECT_URI",
                                    error_message=error_message,
                                    is_key_required=True,
                                    is_value_required=True)
        return uri

    @property
    def redirect_error_uri(self):
        uri = self.get_config_value(key="ERROR_REDIRECT_URI",
                                    error_message=None,
                                    is_key_required=False,
                                    is_value_required=False)
        return uri

    @property
    def signout_uri(self):
        error_message = 'SIGNOUT_URI must be set for logout callback.'
        uri = self.get_config_value(key="SIGNOUT_URI",
                                    error_message=error_message,
                                    is_key_required=True,
                                    is_value_required=True)
        return uri

    @property
    def exempt_methods(self):
        methods = self.get_config_value(key="EXEMPT_METHODS",
                                        error_message=None,
                                        is_key_required=False,
                                        is_value_required=False)
        return methods if methods else ["OPTIONS"]

    @property
    def issuer(self):
        return f"https://login.microsoftonline.com/common/discovery/v2.0"

    @property
    def public_key_uri(self):
        return f"{self.issuer}/keys"

    @property
    def scopes(self):
        _scopes = ["User.Read"]
        # _scopes = []
        return _scopes

    @property
    def get_jwt_key(self):
        auth_manager = self.get_auth_manager
        # load and cache Microsoft OAuth2 JSON Web Key (JWK)
        jwt_key = None
        if not auth_manager.jwt_key:
            jwt_key = requests.get(self.public_key_uri).json()["keys"]
        else:
            jwt_key = auth_manager.jwt_key
        return jwt_key

    @property
    def state(self):
        csrf_state = self.get_config_value(key="STATE",
                                           error_message=None,
                                           is_key_required=False,
                                           is_value_required=False)
        return csrf_state

    @property
    def authority(self):
        return (f"https://login.microsoftonline.com/{self.tenant_id}")

    @property
    def logout_uri(self):
        return (f"{self.authority}/oauth2/v2.0/logout?"
                f"post_logout_redirect_uri={self.signout_uri}")

    @property
    def skip_tokens(self):
        skip_tokens = ["aud",
                       "upn",
                       "iss",
                       "iat",
                       "nbf",
                       "acct",
                       "acr",
                       "aio",
                       "amr",
                       "app_displayname",
                       "appid",
                       "appidacr",
                       "idtyp",
                       "ipaddr",
                       "oid",
                       "onprem_sid",
                       "exp",
                       "platf",
                       "puid",
                       "rh",
                       "scp",
                       "signin_state",
                       "sub",
                       "tenant_region_scope",
                       "tid",
                       "uti",
                       "ver",
                       "wids",
                       "xms_st",
                       "xms_tcdt"]
        return skip_tokens
