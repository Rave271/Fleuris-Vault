from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from sqlalchemy.orm import aliased

from ..models import SecurityEvent, Transaction, User
from ..extensions import db
from ..services.auth import generate_csrf_token, login_required, require_csrf_token
from ..services.security import log_event

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/users")
def users():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view users", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    q = request.args.get("q", "").strip()
    locked_only = request.args.get("locked_only") == "1"
    query = User.query.filter_by(role="customer")
    if q:
        try:
            user_id = int(q)
        except ValueError:
            user_id = None
        if user_id is not None:
            query = query.filter((User.username.ilike(f"%{q}%")) | (User.id == user_id))
        else:
            query = query.filter(User.username.ilike(f"%{q}%"))
    if locked_only:
        query = query.filter(User.locked_until.isnot(None))

    all_users = query.order_by(User.id).all()
    return render_template("users.html", users=all_users, q=q, locked_only=locked_only)


@admin_bp.route("/admin/users/<int:user_id>")
def admin_user_detail(user_id):
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view customer detail", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    customer = User.query.filter_by(id=user_id, role="customer").first()
    if not customer:
        return render_template(
            "error.html",
            title="Not found",
            message="The account or page you requested could not be found.",
        ), 404

    sender = aliased(User)
    recipient = aliased(User)
    transactions = (
        Transaction.query.join(sender, Transaction.from_user == sender.id)
        .join(recipient, Transaction.to_user == recipient.id)
        .filter((Transaction.from_user == user_id) | (Transaction.to_user == user_id))
        .order_by(Transaction.timestamp.desc())
        .limit(10)
        .with_entities(
            Transaction.reference_code,
            Transaction.description,
            Transaction.amount,
            Transaction.status,
            Transaction.timestamp,
            Transaction.from_user.label("from_user_id"),
            Transaction.to_user.label("to_user_id"),
            sender.username.label("from_user"),
            recipient.username.label("to_user"),
        )
        .all()
    )
    transaction_rows = [
        {
            "reference_code": row.reference_code,
            "description": row.description,
            "amount": float(row.amount),
            "status": row.status,
            "timestamp": row.timestamp,
            "from_user_id": row.from_user_id,
            "to_user_id": row.to_user_id,
            "from_user": row.from_user,
            "to_user": row.to_user,
        }
        for row in transactions
    ]
    events = (
        SecurityEvent.query.filter_by(user_id=user_id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "admin_user_detail.html",
        customer=customer,
        transactions=transaction_rows,
        events=events,
        csrf_token=generate_csrf_token(),
    )


@admin_bp.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
def admin_unlock_user(user_id):
    admin = login_required()
    if not admin:
        return redirect(url_for("auth.login"))
    if admin.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to unlock account", admin.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    require_csrf_token(current_app.logger, request.form.get("csrf_token"))

    customer = User.query.filter_by(id=user_id, role="customer").first()
    if not customer:
        return render_template(
            "error.html",
            title="Not found",
            message="The account or page you requested could not be found.",
        ), 404

    customer.failed_login_count = 0
    customer.locked_until = None
    db.session.commit()
    log_event(current_app.logger, "ACCOUNT_UNLOCKED", f"Admin unlocked {customer.username}", admin.id)
    flash(f"{customer.username} has been unlocked.", "success")
    return redirect(url_for("admin.admin_user_detail", user_id=customer.id))
