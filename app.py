from flask import Flask, url_for, session, request, send_from_directory
from flask import render_template, redirect, abort, url_for, flash, Markup
from authlib.integrations.flask_client import OAuth
from authlib.common.errors import AuthlibBaseError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
from flask_wtf.csrf import CSRFProtect

import os
import datetime
import re
import json
import base64

# Initialise flask application
app = Flask(__name__)

# Load config (ensure a secret key has been passed)
app.config.from_object("config")

if app.config.get("SECRET_KEY", None) is None:
    print("[Warning] No secret key has been passed. A random one will be generated for this instance.")
    app.config["SECRET_KEY"] = os.urandom(32).hex()

# Initialise database
db = SQLAlchemy(app)

# Import models after db has been initialised
from models import User, KeyEntry, ConnectionRequest

# Create tables in DB - done after the models have been imported
db.create_all()

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

# Initialise CSRF protection
csrf = CSRFProtect(app)

# Register blueprints
from admin import admin
from api import api
app.register_blueprint(admin)
app.register_blueprint(api)

# Import utils functions after db has been initialised
import utils

# The index page consists of the login screen
@app.route("/")
def login_page():
    user = utils.get_user(request.cookies)

    # If the user is not logged in, display the sign in buttons
    if not user:
        return render_template("index.html")
    else:
        # Otherwise, redirect to the logged in home page
        return redirect(url_for("home_page"))

@app.route("/home")
def home_page():
    user = utils.get_user(request.cookies)

    # Check whether the user is logged in
    if not user:
        flash("You must be logged in to access this page.", "danger")

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # If the user is logged in, display the home page
    # Retrieve the keys for this user
    keys = KeyEntry.query.filter(KeyEntry.key_owner == user.user_id).all()
    
    # Retrieve connection requests for this user
    connection_requests = ConnectionRequest.query.filter(ConnectionRequest.key_owner == user.user_id).all()

    # Remove expired requests
    connection_requests = list(filter(lambda request: not request.is_expired(), connection_requests))

    # Create a list of objects in the format [{"id": 3, "expiryTime": 429819111}]
    connection_requests_times = []
    for con_request in connection_requests:
        connection_requests_times.append({"id": con_request.req_id, "expiryTime": utils.dt2ts(con_request.expiry_date)})

    return render_template("home.html", user=user, keys=keys, connection_requests=connection_requests, connection_requests_times=connection_requests_times, WIREGUARD_MAX_KEYS=app.config["WIREGUARD_MAX_KEYS"])

@app.route("/add_key", methods=["GET", "POST"])
def add_key_page():
    user = utils.get_user(request.cookies)

    # Check whether the user is logged in
    if not user:
        flash("You must be logged in to access this page.", "danger")

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # If the request is GET, return the form to add a new key
    if request.method == "GET":
        return render_template("add_key.html", expiry_times=app.config["EXPIRY_TIMES"])
    else:
        # Otherwise process adding a new key
        # Errors contains a list of errors that will be displayed if the request goes wrong
        errors = []

        # Firstly validate that all the parameters are correct
        # Validate public key
        public_key = request.form.get("public_key", "")
        if not re.match(r"^[0-9a-zA-Z\+\/]{43}=$", public_key):
            errors.append("Public key is not of the expected format.")
        
        # Validate readable name
        readable_name = request.form.get("readable_name", "")
        if len(readable_name) > 32 or not len(readable_name):
            errors.append("Key name must be between 1 and 32 characters long.")
        
        # Validate expiry time
        expiry_time_seconds = request.form.get("expiry_time", "0")
        try:
            expiry_time_seconds = int(expiry_time_seconds)
        except ValueError:
            # Failed to convert to integer, add error
            # This will only happen if the user modifies the webpage/request
            errors.append("Expiry time must be one of the options listed.")
        else:
            # If that was successful, check the expiry time is one of the values listed in the config
            if expiry_time_seconds not in app.config["EXPIRY_TIMES"].values():
                errors.append("Expiry time must be one of the options listed.")
        
        # Check that they don't have more than WIREGUARD_MAX_KEYS already
        existing_keys = KeyEntry.query.filter(KeyEntry.key_owner == user.user_id).count()

        if existing_keys >= app.config["WIREGUARD_MAX_KEYS"]:
            errors.append(f"You cannot add a new key - you already have {existing_keys} keys added.")

        # Check that this key doesn't already exist in the database
        existing_keys = KeyEntry.query.filter(KeyEntry.public_key == public_key).count()

        if existing_keys:
            errors.append(f"This key has already been added.")

        # Now check whether any errors were raised above
        if len(errors):
            # Print error and return to the add key page
            # Use Markup() here to make the <br> appear as actual tags
            flash(Markup("An error occured when trying to add this key: <br>{}".format("<br>".join(errors))), "danger")
            return redirect(url_for("add_key_page"))

        # Convert expiry date to a UTC timestamp
        expiry_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry_time_seconds)
        
        # Everything is good, add the key to the database
        key_entry = KeyEntry(public_key, user.user_id, readable_name, expiry_date)
        db.session.add(key_entry)
        db.session.commit()

        # TODO: Run command to add key to WG

        flash(f"Successfully added {key_entry.readable_name}!", "success")
        return redirect(url_for("home_page"))

@app.route("/revoke_key/<key_id>", methods=["GET", "POST"])
def revoke_key_page(key_id):
    user = utils.get_user(request.cookies)

    # Check whether the user is logged in
    if not user:
        flash("You must be logged in to access this page.", "danger")

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # Check whether the key entered exists
    key_entry = KeyEntry.query.filter(and_(KeyEntry.key_id == key_id, KeyEntry.key_owner == user.user_id)).first()

    if key_entry is None:
        # Display error message and return to home page
        flash("Failed to revoke this key!", "danger")
        return redirect(url_for("home_page"))

    if request.method == "GET":
        # Retrieve key name from database
        return render_template("revoke_key.html", key=key_entry)
    else:
        # Handle removing the key
        # Check that the key passed in the body is still valid
        key_id = request.form.get("key_id", 0)

        # Check whether the key entered exists
        key_entry = KeyEntry.query.filter(and_(KeyEntry.key_id == key_id, KeyEntry.key_owner == user.user_id)).first()

        if key_entry is None:
            # Display error message and return to home page
            flash("Failed to revoke this key!", "danger")
            return redirect(url_for("home_page"))

        key_name = key_entry.readable_name

        # Key exists and the user owns this key, so we can delete it
        db.session.delete(key_entry)
        db.session.commit()

        # Display success message
        flash(f"Successfully revoked {key_name}!", "success")
        return redirect(url_for("home_page"))

@app.route("/view_connection_request/<req_id>", methods=["GET", "POST"])
def view_connection_request_page(req_id):
    user = utils.get_user(request.cookies)

    # Check whether the user is logged in
    if not user:
        flash("You must be logged in to access this page.", "danger")

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # Now, the user must have logged in recently before accessing this page
    # TODO: Move 300 seconds to config
    if user.last_logged_in_time > datetime.datetime.utcnow() + datetime.timedelta(seconds=300):
        # They haven't logged in recently enough, request that they login again
        flash("In order to access this page, you must log in again.", "info")

        # In addition to this, add a redirect parameter to the user session to redirect back to this page
        session["login_redirect"] = url_for("view_connection_request_page", req_id=req_id)

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # Check whether the connection request exists
    connection_request = ConnectionRequest.query.filter(and_(ConnectionRequest.req_id == req_id, ConnectionRequest.key_owner == user.user_id)).first()

    if connection_request is None:
        # Display error message and return to home page
        flash("This connection request does not exist!", "danger")
        return redirect(url_for("home_page"))

    # Check whether they've already answered to this connection request
    if connection_request.request_answered:
        # Display error message and return to home page
        flash("You've already {} this connection request.".format("accepted" if connection_request.request_authenticated else "denied"), "danger")
        return redirect(url_for("home_page"))

    if request.method == "GET":
        return render_template("connection_request.html", connection_request=connection_request)
    else:
        # Check that the key passed in the body is still valid
        req_id = request.form.get("req_id", 0)

        # Check whether the request entered exists
        connection_request = ConnectionRequest.query.filter(and_(ConnectionRequest.req_id == req_id, ConnectionRequest.key_owner == user.user_id)).first()

        if connection_request is None:
            # Display error message and return to home page
            flash("This connection request does not exist!", "danger")
            return redirect(url_for("home_page"))

        # Check whether this request has expired
        if connection_request.is_expired():
            # Display error message and return to home page
            flash("This connection request has expired.", "danger")
            return redirect(url_for("home_page"))

        # Check whether they want to accept/deny the request
        accept_clicked = request.form.get("accept", None) is not None
        deny_clicked = request.form.get("deny", None) is not None

        if not accept_clicked and not deny_clicked:
            # Display error message and return to home page
            flash("Please accept or deny the connection request!", "danger")
            return redirect(url_for("home_page"))

        if accept_clicked:
            # They wish to accept the request, update the entry in the database and display a success message
            connection_request.request_answered = True
            connection_request.request_authenticated = True

            flash(f"Successfully accepted the connection request! Your Wireguard client will now be able to connect to the VPN.", "success")
        else:
            # They wish to deny the request, update the entry in the database and display a success message
            connection_request.request_answered = True
            connection_request.request_authenticated = False

            flash(f"Successfully denied the connection request!", "success")

        db.session.commit()

        return redirect(url_for("home_page"))

@app.route("/login/<name>")
def login(name):
    # Initialise the oauth client based on the name passed (google, twitter etc.)
    client = oauth.create_client(name)
    
    # If no client can be found with that name, display error message
    if not client:
        flash("Please try another login provider!", "danger")
        return redirect(url_for("login_page"))

    # Retrieve the redirect URI
    redirect_uri = url_for("auth", name=name, _external=True)

    # Then redirect to the external login page with our redirect_uri
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/<name>")
def auth(name):
    # Initialise the oauth client based on the name passed (google, twitter etc.)
    client = oauth.create_client(name)
    
    # If no client can be found with that name, display error message
    if not client:
        flash("Please try another login provider!", "danger")
        return redirect(url_for("login_page"))

    # Authorize our access token of our login
    try:
        token = client.authorize_access_token()
    except AuthlibBaseError:
        flash("Something went wrong, please try again.", "danger")
        return redirect(url_for("login_page"))

    # If our token has id_token in it, retrieve our user information from this token
    if "id_token" in token:
        user = client.parse_id_token(token)
    else:
        # Otherwise retrieve our user info via client.userinfo()
        user = client.userinfo()
    
    # Rather than storing all the information from the oauth inside the session, just store essential information
    # TODO: For different identity providers, the unique_id will be different
    # E.g. twitter may be a twitter ID, for google an email, etc.
    unique_id = user["email"]

    # Retrieve the user from the database
    db_user = User.query.filter(User.unique_id == unique_id).first()
    
    # If this user doesn't exist, then error out early. Only users that exist in the Users table should
    # be allowed to get past the login screen.
    if db_user is None:
        flash("This account does not exist. Please contact XYZ if you believe this is a mistake.", "danger")
        return redirect(url_for("login_page"))

    # Check whether the user's account is locked, in which case deny them and display an error message.
    if db_user.locked:
        flash("This account has been locked. Please contact XYZ if you believe this is a mistake.", "danger")
        return redirect(url_for("login_page"))

    # Attempt to get a redirect login, if there isn't a redirect redefined, use the home page.
    redirect_url = session.pop("login_redirect", url_for("home_page"))

    response = redirect(redirect_url)

    # Update user in database with their cookie authentication
    cookie_auth = utils.generate_cookie_auth_value()

    # Create the dictionary that will be placed into the cookie
    cookie_dict = {
        "user_id": db_user.user_id,
        "auth": cookie_auth
    }

    # Set the cookie for the session
    # Our application has a max log in time in case the user edits the cookie
    # Value of cookie is base64(json(cookie_dict))
    response.set_cookie("auth", base64.b64encode(json.dumps(cookie_dict).encode()).decode())

    # Update user with new cookie auth value + latest log in time
    db_user.cookie_auth = cookie_auth
    db_user.cookie_auth_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config["LOGGED_IN_DURATION"])
    db_user.last_logged_in_time = datetime.datetime.utcnow()
    
    # Save to the database
    db.session.commit()

    # Once we've been authorised, redirect to our home page
    return response


@app.route("/logout")
def logout():
    # Redirect to the home page
    response = redirect(url_for("login_page"))

    # Expire the cookie
    response.set_cookie(auth, max_age=0)

    # Attempt to retrieve the user they're currently logged in as
    user = utils.get_user(request.cookies)
    
    if user:
        # Remove the cookie auth value and set the expiry time to 0 (way in the past!)
        user.cookie_auth_expiry = datetime.datetime.fromtimestamp(0)

        db.session.commit()

    # Update the database to be empty
    flash("You have been logged out.", "success")
    return response

# Firebase JS SDK expects firebase-messaging-sw.js to be at the root directory
# This route serves the file from static/js at the root directory
@app.route("/firebase-messaging-sw.js")
def firebase_messaging_js():
    return send_from_directory(os.path.join("static", "js"), "firebase-messaging-sw.js")