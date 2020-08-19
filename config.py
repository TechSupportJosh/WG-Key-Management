import os

# Flask secret key
SECRET_KEY = os.getenv("SECRET_KEY")

# Google OAuth client details
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Twitter OAuth client details
TWITTER_CLIENT_ID = os.getenv('TWITTER_CLIENT_ID')
TWITTER_CLIENT_SECRET = os.getenv('TWITTER_CLIENT_SECRET')

# Database URI
SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/test.db"

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