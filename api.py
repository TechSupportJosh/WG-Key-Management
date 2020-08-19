from flask import Blueprint, render_template, session, url_for, flash, redirect, jsonify, request
from models import User, KeyEntry, ConnectionRequest, FCMDevice
from app import db, app, csrf
from pyfcm import FCMNotification
import datetime

api = Blueprint("api", __name__, url_prefix="/api")
push_service = FCMNotification(api_key=app.config["FCM_API_KEY"])

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

        # Retrieve FCM tokens
        devices = FCMDevice.query.filter(FCMDevice.device_owner == key_owner.user_id).all()
        tokens = [device.device_token for device in devices]
       
        # TODO: Make this message look nice, fix click_action
        push_service.notify_multiple_devices(
            registration_ids=tokens, 
            message_title="New connection request from {}".format(key_entry.readable_name), 
            message_body="Accept this connection request...",
            message_icon="https://cdn3.iconfinder.com/data/icons/wpzoom-developer-icon-set/500/104-512.png",
            click_action="{}".format(url_for("view_connection_request_page", req_id=connection_request.req_id))
        )


        # As the request has just been created, we can return authenticated as false
        return jsonify({
            "authenticated": False
        }), 200

@api.route("/fcm_register", methods=["POST"])
@csrf.exempt
def firebase_cm_register():
    user = session.get("user")

    # Check the user is authenticated
    if user is None:
        return jsonify({
            "message": "Unauthorised"
        }), 401

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "message": "Request must be JSON"
        }), 400
    
    # Check whether the request data contains a device token
    request_data = request.get_json()

    if "device_token" not in request_data:
        return jsonify({
            "message": "Missing parameter 'device_token'"
        }), 400

    # While we're here, clear out old tokens that are no longer valid...
    devices = FCMDevice.query.filter(FCMDevice.device_owner == user["id"]).all()

    # Device_tokens is in the form device_token:FCMDevice
    device_tokens = {}

    for device in devices:
        device_tokens[device.device_token] = device

    # Check whether the ID is already in the database
    if request_data["device_token"] not in device_tokens.keys():
        # Check whether the new device is a valid ID
        if len(push_service.clean_registration_ids([request_data["device_token"]])):
            # It is a valid token, add it to the database
            FCM_device = FCMDevice(user["id"], request_data["device_token"])
            db.session.add(FCM_device)

    # Now take the list of device_tokens keys and pass it to push service to validate tokens
    valid_device_tokens = push_service.clean_registration_ids(device_tokens.keys())

    # Now get the list of invalid device tokens
    invalid_device_tokens = list(set(device_tokens.keys()) - set(valid_device_tokens))

    # Now delete FCMDevices using invalid_device_tokens
    for invalid_token in invalid_device_tokens:
        db.session.delete(device_tokens[invalid_token])

    # Now we can commit all of our changes
    db.session.commit()

    # And finally, return with an empty JSON body and 200 OK!
    return jsonify({}), 200