from flask import Blueprint, render_template, session, url_for, flash, redirect, jsonify
from models import User, KeyEntry
from app import db

admin = Blueprint("admin", __name__, url_prefix="/admin")

@admin.route("/")
def admin_home_page():
    user = session.get("user")

    # Check whether this user is an administrator
    if user is None:
        flash("You must be logged in to access this page.", "danger")

        # Otherwise, redirect to the login page
        return redirect(url_for("login_page"))
    elif not user["is_admin"]:
        flash("You are not authorised to access this page.", "danger")

        # Redirect to the user page
        return redirect(url_for("home_page"))
    
    users = User.query.filter().all()

    return render_template("admin_home.html", users=users)