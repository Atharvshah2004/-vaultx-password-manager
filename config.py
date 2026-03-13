import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback_key")
    MONGO_URI  = os.getenv("MONGO_URI", "mongodb://localhost:27017/password_manager")

    # Session cookie settings
    SESSION_COOKIE_HTTPONLY = True   # JS can't read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection