import secrets
from datetime import datetime, timedelta

import pyotp
from flask import abort, g, session
from werkzeug.security import check_password_hash

from ..extensions import db
from ..models import User
from .security import log_event

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


def set_current_user():
    user_id = session.get("user_id")
    if not user_id:
        g.current_user = None
        return None
    user = User.query.filter_by(id=user_id).first()
    g.current_user = user
    return user


def current_user():
    return getattr(g, "current_user", None)


def login_required():
    return current_user()


def require_admin(user, logger):
    if not user or user.role != "admin":
        if user:
            log_event(logger, "ACCESS_DENIED", "Non-admin attempted admin page", user.id)
        abort(403)


def require_csrf_token(logger, form_token):
    token = session.get("csrf_token")
    if not form_token or not token or form_token != token:
        log_event(logger, "CSRF_BLOCKED", "Invalid or missing CSRF token", session.get("user_id"))
        abort(400)


def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def authenticate_user(logger, username, password, mfa_code):
    user = User.query.filter_by(username=username).first()
    if user and user.locked_until:
        if user.locked_until > datetime.utcnow():
            log_event(logger, "LOGIN_LOCKED", f"Locked account login attempt for {username}", user.id, username=username)
            return None, "Account is temporarily locked. Try again later."
        user.locked_until = None
        db.session.commit()

    if user and check_password_hash(user.password_hash, password):
        if user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(mfa_code, valid_window=1):
                record_failed_login(logger, user, username, "MFA_FAILED", f"Invalid MFA code for {username}")
                return None, "Invalid MFA code."
        user.failed_login_count = 0
        user.locked_until = None
        db.session.commit()
        log_event(logger, "LOGIN_SUCCESS", f"{username} signed in", user.id, username=username)
        return user, None

    if user:
        record_failed_login(logger, user, username, "LOGIN_FAILED", f"Failed login for {username}")
    else:
        log_event(logger, "LOGIN_FAILED", f"Unknown username {username}", username=username)
    return None, "Invalid username or password."


def record_failed_login(logger, user, username, event_type, detail):
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
    db.session.commit()
    log_event(logger, event_type, detail, user.id, username=username)
