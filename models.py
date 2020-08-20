from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer, String,
                        func)

from app import db

import datetime
import pytz

# https://stackoverflow.com/a/13287083
def utc_to_local(utc_dt):
    local_tz = pytz.timezone("Europe/London")
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_tz.normalize(local_dt) # .normalize might be unnecessary

class User(db.Model):
    __tablename__= "users"
    
    user_id = Column(Integer, primary_key=True, autoincrement=True)

    # Unique identifer from oauth logins
    unique_id = Column(String(320))

    # Identifiable name of the user
    name = Column(String(80))

    # Oauth type (Google, Twitter, etc.)
    auth_type = Column(String(16))

    # Store if user is an administrator
    administrator = Column(Boolean, default=False)
    
    # If the account is locked, the user will not be able to log in
    locked = Column(Boolean, default=False)

    def __init__(self, unique_id, name, auth_type, administrator=False, locked=False):
        self.unique_id = unique_id
        self.name = name
        self.auth_type = auth_type
        self.administrator = administrator
        self.locked = False

class KeyEntry(db.Model):
    __tablename__ = "keys"
    __table_args__ = {'sqlite_autoincrement': True}

    key_id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Public keys should also be unique
    # Keys are 32 bytes base64 encoded -> 44 characters long
    public_key = Column(String(44), unique=True)

    # Owner of this key
    key_owner = Column(Integer, ForeignKey("users.user_id"))

    # Name of the key that the user gives it, for example HOME-PC, Work Laptop etc.
    readable_name = Column(String(32))

    # UTC Date for when the key expires
    expiry_date = Column(DateTime)

    # UTC Date for when the key was created
    creation_date = Column(DateTime)

    # TODO: Maybe add features in such as IP of user when this was created?

    def __init__(self, public_key, key_owner, readable_name, expiry_date):
        self.public_key = public_key
        self.key_owner = key_owner
        self.readable_name = readable_name
        self.expiry_date = expiry_date
        self.creation_date = datetime.datetime.utcnow()

    def is_expired(self):
        return datetime.datetime.utcnow() > self.expiry_date

    def expiry_date_string(self):
        return utc_to_local(self.expiry_date).strftime("%c")

    def get_key_owner(self):
        return User.query.filter(User.user_id == self.key_owner).first()

class ConnectionRequest(db.Model):
    __tablename__ = "connection_requests"
    __table_args__ = {'sqlite_autoincrement': True}

    req_id = Column(Integer, primary_key=True, autoincrement=True)

    # The user who requested connection
    key_owner = Column(Integer, ForeignKey("users.user_id"))

    # Public key ID this connection request is using
    key_entry_id = Column(Integer, ForeignKey("keys.key_id"))

    # IP address of the request's sender
    ip_address = Column(String(16))

    # UTC Date for when the request expires
    expiry_date = Column(DateTime)

    # UTC Date for when the request was created
    creation_date = Column(DateTime)

    # Boolean for whether the user has viewed and responded to this request
    request_answered = Column(Boolean, default=False)

    # Boolean for whether this request has been authenticated
    request_authenticated = Column(Boolean, default=False)

    def __init__(self, key_owner, key_entry_id, ip_address, expiry_date):
        self.key_owner = key_owner
        self.key_entry_id = key_entry_id
        self.ip_address = ip_address
        self.expiry_date = expiry_date
        self.creation_date = datetime.datetime.utcnow()
        self.request_answered = False
        self.request_authenticated = False

    def is_authenticated(self):
        """Returns True/False whether the request has been authenticated and that the expiry time
        has not passed. In addition to this, it also checks that the related KeyEntry has not expired"""
        # Check whether our request is authenticated and has not expired
        if not self.request_authenticated or self.is_expired():
            return False

        # Retrieve the key entry
        key_entry = self.get_key_entry()
        
        # Return whether the key_entry is valid and has not expired
        return key_entry is not None and not key_entry.is_expired()

    def is_expired(self):
        return datetime.datetime.utcnow() > self.expiry_date

    def expiry_date_string(self):
        return utc_to_local(self.expiry_date).strftime("%c")

    def get_key_entry(self):
        return KeyEntry.query.filter(KeyEntry.key_id == self.key_entry_id).first()

class FCMDevice(db.Model):
    __tablename__ = "fcm_devices"
    __table_args__ = {'sqlite_autoincrement': True}

    device_id = Column(Integer, primary_key=True, autoincrement=True)

    # The user who requested connection
    device_token = Column(String(500), ForeignKey("users.user_id"), unique=True)

    # The user who requested connection
    device_owner = Column(Integer, ForeignKey("users.user_id"))

    def __init__(self, device_owner, device_token):
        self.device_owner = device_owner
        self.device_token = device_token