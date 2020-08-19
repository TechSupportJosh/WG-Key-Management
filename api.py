from flask import Blueprint, render_template, session, url_for, flash, redirect, jsonify, request
from models import User, KeyEntry, ConnectionRequest
from app import db, app, csrf
import datetime

api = Blueprint("api", __name__, url_prefix="/api")

@api.route("/connection_request", methods=["POST"])
@csrf.exempt
def api_connection_request():
    # TODO: Add authentication to only allow the WG-Proxy access to this endpoint

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "message": "Request must be JSON"
        }), 400

    # Check whether the request includes public_key and ip_address
    request_data = request.get_json()

    if "public_key" not in request_data:
        return jsonify({
            "message": "Missing parameter 'public_key'"
        }), 400

    if "ip_address" not in request_data:
        return jsonify({
            "message": "Missing parameter 'ip_address'"
        }), 400

    public_key = request_data["public_key"]

    # Now search our key entry database to see if we can find this key
    key_entry = KeyEntry.query.filter(KeyEntry.public_key == public_key).first()

    if key_entry is None:
        # Key has not been found in the database.
        return jsonify({
            "message": "Key could not be found"
        }), 404
    
    key_owner = key_entry.get_key_owner()

    if key_owner is None:
        # Owner of the key cannot be found in the database.
        return jsonify({
            "message": "Key owner could not be found"
        }), 404

    # Now check whether there is an existing connection request for this key
    connection_request = ConnectionRequest.query.filter(ConnectionRequest.key_entry_id == key_entry.key_id).first()

    if connection_request is not None:
        # If there's a connection request, check whether it has expired
        if connection_request.is_expired():
            # Connection request is expired, delete it and create a new one
            db.session.delete(connection_request)
            db.session.commit()

            connection_request = None
        else:
            # If the request hasn't expired, return whether the request has been authenticated
            return jsonify({
                "authenticated": connection_request.is_authenticated()
            }), 200

    # If connection request is None, then we can create a new request
    if connection_request is None:
        # Set the expiry date to CONNECTION_REQUEST_EXPIRY_TIME seconds from now
        expiry_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config["CONNECTION_REQUEST_EXPIRY_TIME"])
        
        # Add the connection request to the database
        connection_request = ConnectionRequest(key_owner.user_id, key_entry.key_id, request_data["ip_address"], expiry_date)
        db.session.add(connection_request)
        db.session.commit()

        # TODO: Send push notification here

        # As the request has just been created, we can return authenticated as false
        return jsonify({
            "authenticated": False
        }), 200