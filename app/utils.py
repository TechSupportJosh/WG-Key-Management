import calendar
import base64
import json
import datetime
import os

from models import User

from sqlalchemy import and_

# https://stackoverflow.com/questions/5067218/get-utc-timestamp-in-python-with-datetime
def dt2ts(dt):
    """Converts a datetime object to UTC timestamp

    naive datetime will be considered UTC.

    """

    return calendar.timegm(dt.utctimetuple())

def generate_cookie_auth_value():
    """
        This function generates a base64 encoded string composed from 128 random bytes (172 characters long).
    """
    return base64.b64encode(os.urandom(128)).decode()

def get_user(cookies):
    """
        This function takes in cookies from a request
        and retrieves the User object based on the user_id in 
        the cookie from the database and returns it - assuming the
        auth value matches the one in the database.

        Returns a User object on success, otherwise returns None
    """
    # Check whether there is an auth cookie
    auth_cookie = cookies.get("auth", None)

    if auth_cookie is None:
        return None
        
    # Decode value from base64
    try:
        auth_cookie = base64.b64decode(auth_cookie)
    except binascii.Error:
        return None
        
    # Now convert from JSON
    try:
        auth_cookie = json.loads(auth_cookie)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
        
    # Check whether token contains user ID and authentication string
    if "user_id" not in auth_cookie or "auth" not in auth_cookie:
        return None
        
    # Return what matches user_id, auth & ensure that the current time isn't after the expiry
    return User.query.filter(
        and_(User.user_id == auth_cookie["user_id"], 
             User.cookie_auth == auth_cookie["auth"], User.cookie_auth_expiry > datetime.datetime.utcnow()
            )
        ).first()
