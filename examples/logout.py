from flask import Flask
from flask import redirect
from flask import url_for
from flask import session
from flask import jsonify
from flask_ms_oauth2 import MSOAuth2Manager
from flask_ms_oauth2 import login_handler
from flask_ms_oauth2 import logout_handler
from flask_ms_oauth2 import callback_handler

app = Flask(__name__)
app.secret_key = "my super secret key"

# Setup the flask-ms-oauth2 extention
app.config['CLIENT_ID'] = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config['CLIENT_SECRET'] = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config['TENANT_ID'] = "xxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config["ERROR_REDIRECT_URI"] = "page500"        # Optional
app.config["STATE"] = "mysupersecrethash"   # Optional

# Specify this url in Callback URLs section of Appllication client settings within Microsoft OAuth2 Sevice. Post login application will redirect to this URL
app.config['REDIRECT_URI'] = "https://yourdomainhere/auth/callback"

# Specify this url in Sign out URLs section of Appllication client settings. Post logout application will redirect to this URL
app.config['SIGNOUT_URI'] = "https://yourdomainhere/login"


msoauth2 = MSOAuth2Manager(app)


@app.route('/login', methods=['GET'])
def login():
    print("Do the stuff before login to Microsoft Oauth2 Service")
    response = redirect(url_for("msoauth2login"))
    return response


@app.route('/logout', methods=['GET'])
def logout():
    print("Do the stuff before logout from Microsoft Oauth2 Service")
    response = redirect(url_for("msoauth2logout"))
    return response


# Use @login_handler decorator on Microsoft OAuth2 login route
@app.route('/msoauth2/login', methods=['GET'])
@login_handler
def msoauth2login():
    pass


@app.route('/home', methods=['GET'])
def home():
    current_user = session["username"]
    return jsonify(logged_in_as=current_user), 200


# Use @callback_handler decorator on Microsoft OAuth2 callback route
@app.route('/auth/callback', methods=['GET'])
@callback_handler
def callback():
    for key in list(session.keys()):
        print(f"Value for {key} is {session[key]}")
    response = redirect(url_for("home"))
    return response


# Use @logout_handler decorator on Microsoft OAuth2 logout route
@app.route('/msoauth2/logout', methods=['GET'])
@logout_handler
def msoauth2logout():
    pass


@app.route('/page500', methods=['GET'])
def page500():
    return jsonify(Error="Something went wrong"), 500


if __name__ == '__main__':
    app.run(debug=True)
