from functools import wraps
from flask import g, request, redirect, url_for, session, flash

from app import app
import utils

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            # Set login redirect to the URL they tried accessing
            session["login_redirect"] = request.url

            flash("You must be logged in to access this page.", "danger")

            # Redirect to the login page
            return redirect(url_for("login_page"))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            # Set login redirect to the URL they tried accessing
            session["login_redirect"] = request.url

            flash("You must be logged in to access this page.", "danger")

            # Redirect to the login page
            return redirect(url_for("login_page"))
        elif not g.user.administrator:
            flash("You are not authorised to access this page.", "danger")

            # Redirect to the user page
            return redirect(url_for("home_page"))

        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_user_from_cookie():
    g.user = utils.get_user(request.cookies)