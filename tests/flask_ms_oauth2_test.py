from flask_ms_oauth2.config import Config
from flask_ms_oauth2.decorators import update_session
from .server import app
from .server import app_exception
from .server import app_lazy
import pytest
from flask import Flask
from flask import session
from datetime import datetime


def test_oauth2_config(app):
    with app.test_request_context():
        config = Config()

        app.config['CLIENT_ID'] = "123drfthinvdr57opQWerv56"
        app.config['CLIENT_SECRET'] = "mysupersecretclientvalue"
        app.config['TENANT_ID'] = "34534dfsdrftsdfsopQWerv56"
        app.config['REDIRECT_URI'] = "http://localhost:5000/auth/callback"
        app.config['SIGNOUT_URI'] = "http://localhost:5000/login"
        app.config['ERROR_REDIRECT_URI'] = "page500"
        app.config['STATE'] = "mysupersecrethash"

        auth_mgr = config.get_auth_manager
        auth_mgr.jwt_key = "mypublickkey"

        assert config.client_secret == "mysupersecretclientvalue"
        assert config.tenant_id == "34534dfsdrftsdfsopQWerv56"
        assert config.client_id == "123drfthinvdr57opQWerv56"
        assert config.redirect_uri == "http://localhost:5000/auth/callback"
        assert config.redirect_error_uri == "page500"
        assert config.client_secret == "mysupersecretclientvalue"
        assert config.signout_uri == "http://localhost:5000/login"
        assert auth_mgr.jwt_key == config.get_jwt_key
        assert config.exempt_methods == ['OPTIONS']

        assert config.logout_uri == (f"{config.authority}/oauth2/v2.0/logout?"
                                     f"post_logout_redirect_uri={config.signout_uri}")

        assert config.authority == (
            f"https://login.microsoftonline.com/{config.tenant_id}")
        assert config.issuer == f"https://login.microsoftonline.com/common/discovery/v2.0"
        assert config.public_key_uri == (f"{config.issuer}/keys")


def test_oauth2_exception(app_exception):
    with app_exception.test_request_context():
        config = Config()
        try:
            _ = config.get_auth_manager
        except RuntimeError as e:
            assert str(
                e) == "Microsoft OAuth2 extention is not registerd with Flask application."

        try:
            app_exception.config['CLIENT_ID'] = ""
            _ = config.client_id
        except RuntimeError as e:
            assert str(
                e) == "CLIENT_ID must be set to validate the audience claim."

        try:
            _ = config.client_secret
        except RuntimeError as e:
            assert str(
                e) == "CLIENT_SECRET must be set to validate the audience claim."


def test_0auth2_lazy(app_lazy):
    with app_lazy.test_request_context():
        config = Config()
        app_lazy.config['ERROR_REDIRECT_URI'] = "page500"

        assert config.redirect_error_uri == "page500"


def test_session(app):
    with app.test_request_context():
        datetime_now = datetime.now()
        update_session(username="myusername",
                       id="myuserid",
                       email='myemail@domain.com',
                       expires=datetime_now,
                       refresh_token="mysupersecretrefreshtoken",
                       access_token="mysupersecretaccesstoken",
                       provider_type="msoauth2",
                       saml_assertions=[{"profile": ["g1", "g2"]}])
        assert session['username'] == "myusername"
        assert session['id'] == "myuserid"
        assert session['email'] == "myemail@domain.com"
        assert session['expires'] == datetime_now
        assert session['refresh_token'] == "mysupersecretrefreshtoken"
        assert session['access_token'] == "mysupersecretaccesstoken"
        assert session['provider_type'] == "msoauth2"
        assert session['saml_assertions'] == [{"profile": ["g1", "g2"]}]
