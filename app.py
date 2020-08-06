from flask import Flask, url_for, session
from flask import render_template, redirect, abort, url_for
from authlib.integrations.flask_client import OAuth

import os
import datetime
import pytz

# Initialise flask application
app = Flask(__name__)

# Load config (ensure a secret key has been passed)
app.config.from_object("config")

if app.config.get("SECRET_KEY", None) is None:
    print("[Warning] No secret key has been passed. A random one will be generated for this instance.")
    app.config["SECRET_KEY"] = os.urandom(32).hex()

# Initialise oauth for our flask application
oauth = OAuth(app)

# Register OAuth for Google
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

# https://stackoverflow.com/a/13287083
def utc_to_local(utc_dt):
    local_tz = pytz.timezone("Europe/London")
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_tz.normalize(local_dt) # .normalize might be unnecessary

# The index page consists of the login screen
@app.route("/")
def login_page():
    user = session.get("user")

    # If the user is not logged in, display the sign in buttons
    if not user:
        return render_template("index.html")
    else:
        # Otherwise, redirect to the logged in home page
        return redirect(url_for("home_page"))

@app.route("/home")
def home_page():
    user = session.get("user")

    # If the user is logged in, display the home page
    if user:
        # Retrieve the keys for this user
        # TODO: Retrieve keys from the database

        keys = [{
            "readable_name": "HOME-PC",
            "public_key": "EXAMPLEKEY_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "expiry_date": utc_to_local(datetime.datetime.utcnow()).strftime("%c")
        }]

        print(keys)
        return render_template("home.html", user=user, keys=keys, WIREGUARD_MAX_KEYS=app.config["WIREGUARD_MAX_KEYS"])
    else:
        # Otherwise, redirect to the login page
        return redirect(url_for("login_page"))

@app.route("/login/<name>")
def login(name):
    # Initialise the oauth client based on the name passed (google, twitter etc.)
    client = oauth.create_client(name)
    
    # If no client can be found with that name, return 404
    if not client:
        abort(404)

    # Retrieve the redirect URI
    redirect_uri = url_for("auth", name=name, _external=True)

    # Then redirect to the external login page with our redirect_uri
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/<name>")
def auth(name):
    # Initialise the oauth client based on the name passed (google, twitter etc.)
    client = oauth.create_client(name)
    
    # If no client can be found with that name, return 404
    if not client:
        abort(404)

    # Authorize our access token of our login
    token = client.authorize_access_token()
    # If our token has id_token in it, retrieve our user information from this token
    if "id_token" in token:
        user = client.parse_id_token(token)
    else:
        # Otherwise retrieve our user info via client.userinfo()
        user = client.userinfo()

    # Update our session token with this user
    session["user"] = user

    # Once we've been authorised, redirect to our home page
    return redirect(url_for("home_page"))


@app.route("/logout")
def logout():
    # Remove our user from the session token
    session.pop("user", None)

    # Redirect to the home page
    return redirect(url_for("login_page"))
