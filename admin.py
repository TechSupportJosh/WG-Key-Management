from flask import Blueprint, render_template, session, url_for, flash, redirect, jsonify, request
from werkzeug.utils import secure_filename

from models import User, KeyEntry
from app import db, app

import csv
import os

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

@admin.route("/add_users")
def admin_add_users():
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
    
    return render_template("admin_add_users.html")

@admin.route("/add_users_csv", methods=["POST"])
def admin_add_users_csv():
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
    
    # Check whether file has been passed
    if "csv_file" not in request.files:
        flash("Please upload a valid CSV file.", "danger")
        return redirect(url_for("admin.admin_add_users"))

    csv_file = request.files["csv_file"]

    # if user does not select file, browser also
    # submit an empty part without filename
    if csv_file.filename == "" or not csv_file:
        flash("Please upload a valid CSV file.", "danger")
        return redirect(url_for("admin.admin_add_users"))

    # Use secure_filename to prevent any filename trickery
    file_name = secure_filename(csv_file.filename)

    # Save the file
    csv_file.save(os.path.join(app.config["CSV_UPLOAD_FOLDER"], file_name))

    # csv_file now contains the absolute file path of the CSV file
    csv_file = os.path.join(app.config["CSV_UPLOAD_FOLDER"], file_name)

    # Now attempt to parse it as a CSV
    # Store new users in a list
    users = []

    # Store the row indexes where something went wrong
    # Format is (row index, error)
    invalid_row_indexes = []

    with open(csv_file, "r") as file:
        # Open file in CSV reader
        try:
            csv_reader = csv.reader(file)
            for row_index, user in enumerate(csv_reader):
                # Firstly check whether there are 3 parameters (unique id, name, auth type)
                if len(user) != 3:
                    invalid_row_indexes.append((row_index, "Incorrect number of elements"))
                    continue

                # Now check whether the auth type is valid
                if user[2] not in app.config["SUPPORTED_AUTH_TYPES"]:
                    invalid_row_indexes.append((row_index, "Invalid auth type"))
                    continue
                
                # Add the user to our users array in the form (row index, User object)
                users.append((row_index, User(user[0], user[1], user[2])))
        except UnicodeDecodeError as e:
            # If something has gone wrong trying to parse the file, make sure we catch it
            # This prevents something sitting in tmp, which could be used maliciously
            flash("Failed to parse CSV file, please try again and check the format of the CSV.", "danger")

    # TODO: Add error messages for instances that failed to be commited to databases
    if len(users):
        db.session.add_all([user[1] for user in users])
        db.session.commit()

        flash("Successfully added {} users.".format(len(users)), "success")

    # TODO: Improve error message displays
    error_message = ", ".join(["row {} - {}".format(error[0] + 1, error[1]) for error in invalid_row_indexes])

    if len(invalid_row_indexes):
        flash("Failed to import users. Errors: {}".format(error_message), "danger")

    # Now delete the uploaded CSV file
    os.remove(csv_file)

    return redirect(url_for("admin.admin_add_users"))