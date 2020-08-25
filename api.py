from flask import Blueprint, render_template, session, url_for, flash, redirect, jsonify, request
from models import User, KeyEntry, ConnectionRequest, FCMDevice
from app import db, app, csrf
from pyfcm import FCMNotification

import datetime
import utils

api = Blueprint("api", __name__, url_prefix="/api")
push_service = FCMNotification(api_key=app.config["FCM_API_KEY"])

@api.route("/connection_request", methods=["POST"])
@csrf.exempt
def api_connection_request():
    auth_value = request.headers.get("X-Authentication", None)

    # Check the request has a X-Authentication header and it matches CONNECTION_REQUEST_SECRET
    if auth_value is None or auth_value != app.config["CONNECTION_REQUEST_SECRET"]:
        return jsonify({
            "message": "Unauthorised"
        }), 401

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

    # If the user's account is locked, do not check for a connection request
    if key_owner.locked:
        # Owner of this key's account is locked
        return jsonify({
            "message": "Key owner's account is locked"
        })

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
            # If the request hasn't expired, return status code 200 (OK)
            return jsonify({
                "authenticated": connection_request.is_authenticated()
            }), 200 if connection_request.is_authenticated() else 401

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
        }), 401

@api.route("/fcm_register", methods=["POST"])
@csrf.exempt
def firebase_cm_register():
    user = utils.get_user(request.cookies)

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
    devices = FCMDevice.query.filter(FCMDevice.device_owner == user.user_id).all()

    # Device_tokens is in the form device_token:FCMDevice
    device_tokens = {}

    for device in devices:
        device_tokens[device.device_token] = device

    # Check whether the ID is already in the database
    if request_data["device_token"] not in device_tokens.keys():
        # Check whether the new device is a valid ID
        if len(push_service.clean_registration_ids([request_data["device_token"]])):
            # It is a valid token, add it to the database
            FCM_device = FCMDevice(user.user_id, request_data["device_token"])
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

@api.route("/lock_account", methods=["POST"])
def admin_lock_account():
    user = utils.get_user(request.cookies)

    # If the user isn't logged in or an administrator, return Unauthorised, 401
    if user is None or not user.administrator:
        return jsonify({
            "success": False,
            "message": "Unauthorised"
        }), 401

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "success": False,
            "message": "Request must be JSON"
        }), 400
    
    # Check whether the request includes user_id parameter
    request_data = request.get_json()

    user_id = request_data.get("user_id")
    if user_id is None or not isinstance(user_id, int):
        # user_id is not the correct type, return Bad Request 400
        return jsonify({
            "success": False,
            "message": "Invalid parameter user_id"
        }), 400

    # Check whether the request includes whether the accounts should be locked, unlocked or toggled
    lock_operation = request_data.get("operation")
    if lock_operation not in ["lock", "unlock", "toggle"]:
        # operation is not a valid input, return Bad Request 400
        return jsonify({
            "success": False,
            "message": "Invalid parameter operation - must be lock, unlock or toggle"
        }), 400
    
    # If everything is good so far, we can then proceed
    request_user = User.query.filter(User.user_id == user_id).first()

    # Check whether this user exists
    if request_user is None:
        return jsonify({
            "success": False,
            "message": "User does not exist"
        }), 404

    # Check the user isn't locking themselves
    if request_user.user_id == user.user_id:
        return jsonify({
            "success": False,
            "message": "Cannot lock yourself"
        }), 400

    request_user.locked = not request_user.locked if lock_operation == "toggle" else (lock_operation == "lock") # If lock operation is lock, then set locked to true, otherwise unlock them (set to false)

    # Also set cookie_auth_expiry to ensure users that are already logged in are invalidated
    request_user.cookie_auth_expiry = datetime.datetime.fromtimestamp(0)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Operation was successful."
    }), 200

@api.route("/delete_account", methods=["POST"])
def admin_delete_account():
    user = utils.get_user(request.cookies)

    # If the user isn't logged in or an administrator, return Unauthorised, 401
    if user is None or not user.administrator:
        return jsonify({
            "success": False,
            "message": "Unauthorised"
        }), 401

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "success": False,
            "message": "Request must be JSON"
        }), 400
    
    # Check whether the request includes user_id parameter
    request_data = request.get_json()

    user_id = request_data.get("user_id")
    if user_id is None or not isinstance(user_id, int):
        # user_id is not the correct type, return Bad Request 400
        return jsonify({
            "success": False,
            "message": "Invalid parameter user_id"
        }), 400

    # If everything is good so far, we can then proceed
    request_user = User.query.filter(User.user_id == user_id).first()

    # Check whether this user exists
    if request_user is None:
        return jsonify({
            "success": False,
            "message": "User does not exist"
        }), 404

    # Check the user isn't deleting themselves
    if request_user.user_id == user.user_id:
        return jsonify({
            "success": False,
            "message": "Cannot lock yourself"
        }), 400

    # Check the user isn't another administrator
    # TODO: Should there be another administraotr role that has ultimate power?
    if request_user.administrator:
        return jsonify({
            "success": False,
            "message": "Cannot delete an administrator"
        }), 400

    # Delete the user
    db.session.delete(request_user)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Operation was successful."
    }), 200


# The API endpoint for revoking keys is used for the administrator control panel
# This endpoint is NOT used when a user navigates to /revoke_key
@api.route("/revoke_key", methods=["POST"])
def admin_revoke_key():
    user = utils.get_user(request.cookies)

    # If the user isn't logged in or an administrator, return Unauthorised, 401
    if user is None or not user.administrator:
        return jsonify({
            "success": False,
            "message": "Unauthorised"
        }), 401

    # Check whether the request is json
    if not request.is_json:
        return jsonify({
            "success": False,
            "message": "Request must be JSON"
        }), 400
    
    # Check whether the request includes key_id parameter
    request_data = request.get_json()

    key_id = request_data.get("key_id")
    if key_id is None or not isinstance(key_id, int):
        # key_id is not the correct type, return Bad Request 400
        return jsonify({
            "success": False,
            "message": "Invalid parameter key_id"
        }), 400

    # If everything is good so far, we can then proceed
    request_key = KeyEntry.query.filter(KeyEntry.key_id == key_id).first()

    # Check whether this key exists
    if request_key is None:
        return jsonify({
            "success": False,
            "message": "Key does not exist"
        }), 404
    
    key_owner = request_key.get_key_owner()

    # Check the user isn't another administrator
    # TODO: Should there be another administraotr role that has ultimate power?
    if key_owner.administrator and key_owner.user_id != user.user_id:
        return jsonify({
            "success": False,
            "message": "Cannot delete an administrator's keys"
        }), 400

    # Delete the key
    db.session.delete(request_key)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Operation was successful."
    }), 200