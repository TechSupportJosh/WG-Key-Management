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
        self.locked = True


class KeyEntry(db.Model):
    __tablename__ = "keys"

    key_id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Public keys should also be unique
    # Keys are 32 bytes base64 encoded -> 44 characters long
    public_key = Column(String(44), unique=True)

    # Owner of this key
    key_owner = Column(String(320), ForeignKey("users.user_id"))

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