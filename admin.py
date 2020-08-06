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

# API Endpoints
# These endpoints are used by javascript via AJAX
# Therefore, these require json inputs

# TODO: Should this endpoint support doing multiple accounts at once?
# Or should the website send 30 /lock_account requests - allowing it to determine if one fails?
@admin.route("/lock_accounts")
def admin_lock_accounts(methods=["POST"]):
    user = session.get("user")

    # If the user isn't logged in or an administrator, return Unauthorised, 401
    if user is None or not user["is_admin"]:
        return jsonify({
            "message": "Unauthorised"
        }), 401

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "message": "Request must be JSON"
        }), 405
    
    # Check whether the request includes user_ids parameter
    request_data = request.get_json()

    user_ids = request_data.get("user_ids")
    if user_ids is None or not isinstance(user_ids, list):
        # user_ids is not the correct type, return Bad Request 400
        return jsonify({
            "message": "Invalid parameter user_ids"
        }), 400

    # Check whether the request includes whether the accounts should be locked, unlocked or toggled
    lock_operation = request_data.get("operation")
    if lock_operation not in ["lock", "unlock", "toggle"]:
        # operation is not a valid input, return Bad Request 400
        return jsonify({
            "message": "Invalid parameter operation - must be lock, unlock or toggle."
        }), 400
    
    # If everything is good so far, we can then proceed
    # TODO: Add error handling
    User.query.filter(User.user_id.in_(user_ids)).update({
        User.locked: not User.locked if lock_operation == "toggle" else (lock_operation == "lock") # If lock operation is lock, then set locked to true, otherwise unlock them (set to false)
    })

    db.session.commit()

    return jsonify({
        "message": "Operation was successful."
    }), 200