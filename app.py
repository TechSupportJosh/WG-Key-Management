from flask import Flask, url_for, session, request
from flask import render_template, redirect, abort, url_for, flash, Markup
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_

import os
import datetime
import re

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
from models import User, KeyEntry

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

# Register blueprints
from admin import admin
app.register_blueprint(admin)

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
        keys = KeyEntry.query.filter(KeyEntry.key_owner == user["id"]).all()
        
        return render_template("home.html", user=user, keys=keys, WIREGUARD_MAX_KEYS=app.config["WIREGUARD_MAX_KEYS"])
    else:
        flash("You must be logged in to access this page.", "danger")

        # Otherwise, redirect to the login page
        return redirect(url_for("login_page"))

@app.route("/add_key", methods=["GET", "POST"])
def add_key_page():
    user = session.get("user")

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
        existing_keys = KeyEntry.query.filter(KeyEntry.key_owner == user["unique_id"]).count()

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
        key_entry = KeyEntry(public_key, user["id"], readable_name, expiry_date)
        db.session.add(key_entry)
        db.session.commit()

        # TODO: Run command to add key to WG

        flash(f"Successfully added {key_entry.readable_name}!", "success")
        return redirect(url_for("home_page"))

@app.route("/revoke_key/<key_id>", methods=["GET", "POST"])
def revoke_key_page(key_id):
    user = session.get("user")

    # Check whether the user is logged in
    if not user:
        flash("You must be logged in to access this page.", "danger")

        # Redirect to the login page
        return redirect(url_for("login_page"))

    # Check whether the key entered exists
    key_entry = KeyEntry.query.filter(and_(KeyEntry.key_id == key_id, KeyEntry.key_owner == user["id"])).first()

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
        key_entry = KeyEntry.query.filter(and_(KeyEntry.key_id == key_id, KeyEntry.key_owner == user["id"])).first()

        if key_entry is None:
            # Display error message and return to home page
            flash("Failed to revoke this key!", "danger")
            return redirect(url_for("revoke_key_page", key_id=key_id))

        key_name = key_entry.readable_name

        # Key exists and the user owns this key, so we can delete it
        db.session.delete(key_entry)
        db.session.commit()

        # Display success message
        flash(f"Successfully revoked {key_name}!", "success")
        return redirect(url_for("home_page"))

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
    
    # Rather than storing all the information from the oauth inside the session, just store essential information
    # TODO: For different identity providers, the unique_id will be different
    session_user = {
        "name": user["name"],
        "unique_id": user["email"]
    }

    # Now check whether this unique_id exists in the user table
    db_user = User.query.filter(User.unique_id == session_user["unique_id"]).first()
    
    # If this user doesn't exist, then error out early. Only users that exist in the Users table should
    # be allowed to get past the login screen.
    if db_user is None:
        flash("This account does not exist. Please contact XYZ if you believe this is a mistake.", "danger")
        return redirect(url_for("login_page"))

    # Check whether the user's account is locked, in which case deny them and display an error message.
    if db_user.locked:
        flash("This account has been locked. Please contact XYZ if you believe this is a mistake.", "danger")
        return redirect(url_for("login_page"))
        
    # Update user with database parameters
    session_user["id"] = db_user.user_id
    session_user["is_admin"] = db_user.administrator

    # Update our session token with this user
    session["user"] = session_user

    # Once we've been authorised, redirect to our home page
    return redirect(url_for("home_page"))


@app.route("/logout")
def logout():
    # Remove our user from the session token
    session.pop("user", None)

    # Redirect to the home page
    return redirect(url_for("login_page"))
