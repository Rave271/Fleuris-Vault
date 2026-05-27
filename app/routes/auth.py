from flask import Blueprint, redirect, render_template, request, session, url_for, current_app
import base64
import io

import pyotp
import qrcode
from qrcode.image.svg import SvgImage

from ..extensions import db
from ..services.auth import authenticate_user, login_required, set_current_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.before_app_request
def load_user():
    set_current_user()


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    existing_user = login_required()

    # If already logged in, redirect based on role
    if existing_user:
        if existing_user.role == "admin":
            return redirect(url_for("admin.users"))
        return redirect(url_for("core.dashboard"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        mfa_code = request.form.get("mfa_code", "").strip()

        user, error = authenticate_user(
            current_app.logger,
            username,
            password,
            mfa_code
        )

        if user:
            if user.role == "admin":
                error = "Access denied."
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user.id
                session["username"] = user.username
                return redirect(url_for("core.dashboard"))

    return render_template("login.html", error=error)

@auth_bp.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    existing_user = login_required()
    if existing_user:
        if existing_user.role == "admin":
            return redirect(url_for("admin.users"))
        return redirect(url_for("core.dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        mfa_code = request.form.get("mfa_code", "").strip()

        user, error = authenticate_user(
            current_app.logger,
            username,
            password,
            mfa_code
        )

        if user:
            if user.role != "admin":
                error = "Access denied. This portal is for administrators only."
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user.id
                session["username"] = user.username
                return redirect(url_for("admin.users"))

    return render_template("admin_login.html", error=error)

@auth_bp.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))

    secret = user.totp_secret
    if request.method == "POST":
        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.session.commit()
        from ..services.security import log_event

        log_event(current_app.logger, "MFA_ENABLED", "MFA secret generated", user.id, username=user.username)

    qr_data = None
    if secret:
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.username,
            issuer_name="Fleuris Vault",
        )
        qr_image = qrcode.make(provisioning_uri, image_factory=SvgImage)
        buffer = io.BytesIO()
        qr_image.save(buffer)
        qr_data = base64.b64encode(buffer.getvalue()).decode("ascii")

    return render_template("mfa_setup.html", secret=secret, user=user, qr_data=qr_data)


@auth_bp.route("/logout")
def logout():
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        from ..services.security import log_event

        log_event(current_app.logger, "LOGOUT", "User signed out", user_id, username=session.get("username"))
    return redirect(url_for("core.index"))
