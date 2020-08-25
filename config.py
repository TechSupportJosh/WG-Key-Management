import os
import base64

# Flask secret key
SECRET_KEY = os.getenv("SECRET_KEY")

SQRL_KEY = base64.b64decode(os.getenv("SQRL_KEY"))

# Google OAuth client details
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Twitter OAuth client details
TWITTER_CLIENT_ID = os.getenv('TWITTER_CLIENT_ID')
TWITTER_CLIENT_SECRET = os.getenv('TWITTER_CLIENT_SECRET')

# Google Firebase Cloud Messaging configuration
FCM_API_KEY = os.getenv("FCM_API_KEY")

# A random string that allows requests to /api/connection_request
# This value must be sent the connection request handler via the header X-Authenticate
CONNECTION_REQUEST_SECRET = os.getenv("CONNECTION_REQUEST_SECRET") or os.urandom(32)

# Database URI
SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/test.db"

# How long the user will remain logged in for in seconds
LOGGED_IN_DURATION = 3600

# Supported OAUTH types
SUPPORTED_AUTH_TYPES = ["google"]

# Folder that CSVs are uploaded to 
CSV_UPLOAD_FOLDER = "/tmp/"

# Maximum keys a user may have
WIREGUARD_MAX_KEYS = 5

# The options that users can pick for how long their keys are valid for
# Format: Label Display : Time in Seconds
EXPIRY_TIMES = {
    "1 Hour": 3600,
    "6 Hours": 3600 * 6,
    "1 Day": 3600 * 24
}

# Time in seconds before a connection request will expire
CONNECTION_REQUEST_EXPIRY_TIME = 300