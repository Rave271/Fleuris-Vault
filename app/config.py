import os


class Config:
    SECRET_KEY = os.environ.get("AEGIS_SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://raghavverma@localhost/fleuris_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 30
    LOG_DIR = os.environ.get("LOG_DIR", "logs")
