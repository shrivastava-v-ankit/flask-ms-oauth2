import pytest
from flask import Flask
from flask_ms_oauth2 import MSOAuth2Manager


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    _ = MSOAuth2Manager(app)
    app.secret_key = "my super secret key"
    return app


@pytest.fixture(scope='function')
def app_exception():
    app = Flask(__name__)
    _ = MSOAuth2Manager()
    return app


@pytest.fixture(scope='function')
def app_lazy():
    app = Flask(__name__)
    auth_manager = MSOAuth2Manager()
    auth_manager.init(app)
    return app
