import csv
import io
from datetime import datetime

from flask import Blueprint, current_app, redirect, render_template, request, url_for, Response
from sqlalchemy import func
from sqlalchemy.orm import aliased

from ..models import SecurityEvent, Transaction, User
from ..services.auth import login_required
from ..services.security import log_event

core_bp = Blueprint("core", __name__)


@core_bp.route("/")
def index():
    return render_template("index.html")


@core_bp.route("/dashboard")
def dashboard():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))

    if user.role == "admin":
        customer_count = User.query.filter_by(role="customer").count()
        event_count = SecurityEvent.query.count()
        locked_count = User.query.filter_by(role="customer").filter(User.locked_until.isnot(None)).count()
        recent_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(5).all()

        start_of_day = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        transfers_today = Transaction.query.filter(Transaction.timestamp >= start_of_day).count()
        failed_logins_today = SecurityEvent.query.filter(
            SecurityEvent.event_type.in_(["LOGIN_FAILED", "MFA_FAILED", "LOGIN_LOCKED"]),
            SecurityEvent.created_at >= start_of_day,
        ).count()

        return render_template(
            "admin_dashboard.html",
            user=user,
            customer_count=customer_count,
            event_count=event_count,
            locked_count=locked_count,
            transfers_today=transfers_today,
            failed_logins_today=failed_logins_today,
            recent_events=recent_events,
        )

    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    money_sent_month = (
        Transaction.query.filter(
            Transaction.from_user == user.id,
            Transaction.timestamp >= start_of_month,
        )
        .with_entities(func.coalesce(func.sum(Transaction.amount), 0))
        .scalar()
    )
    money_received_month = (
        Transaction.query.filter(
            Transaction.to_user == user.id,
            Transaction.timestamp >= start_of_month,
        )
        .with_entities(func.coalesce(func.sum(Transaction.amount), 0))
        .scalar()
    )

    last_login = (
        SecurityEvent.query.filter_by(user_id=user.id, event_type="LOGIN_SUCCESS")
        .order_by(SecurityEvent.created_at.desc())
        .first()
    )

    sender = aliased(User)
    recipient = aliased(User)
    transactions = (
        Transaction.query.join(sender, Transaction.from_user == sender.id)
        .join(recipient, Transaction.to_user == recipient.id)
        .filter((Transaction.from_user == user.id) | (Transaction.to_user == user.id))
        .order_by(Transaction.timestamp.desc())
        .limit(5)
        .with_entities(
            Transaction.id,
            Transaction.reference_code,
            Transaction.amount,
            Transaction.status,
            Transaction.timestamp,
            sender.username.label("from_user"),
            recipient.username.label("to_user"),
        )
        .all()
    )
    transaction_rows = [
        {
            "id": row.id,
            "reference_code": row.reference_code,
            "amount": float(row.amount),
            "status": row.status,
            "timestamp": row.timestamp,
            "from_user": row.from_user,
            "to_user": row.to_user,
        }
        for row in transactions
    ]

    # Build monthly spending for the last 6 months for chart (stdlib only)
    import calendar as _cal
    monthly_data = []
    now = datetime.utcnow()
    for i in range(5, -1, -1):
        # subtract i months
        month = now.month - i
        year = now.year
        while month <= 0:
            month += 12
            year -= 1
        _, last_day = _cal.monthrange(year, month)
        month_start = datetime(year, month, 1)
        # month_end: first day of next month
        if month == 12:
            month_end = datetime(year + 1, 1, 1)
        else:
            month_end = datetime(year, month + 1, 1)
        sent = (Transaction.query
                .filter(Transaction.from_user == user.id,
                        Transaction.timestamp >= month_start,
                        Transaction.timestamp < month_end)
                .with_entities(func.coalesce(func.sum(Transaction.amount), 0))
                .scalar())
        received = (Transaction.query
                    .filter(Transaction.to_user == user.id,
                            Transaction.timestamp >= month_start,
                            Transaction.timestamp < month_end)
                    .with_entities(func.coalesce(func.sum(Transaction.amount), 0))
                    .scalar())
        monthly_data.append({
            "label": month_start.strftime("%b"),
            "sent": float(sent or 0),
            "received": float(received or 0),
        })

    # Recent security events for this user
    user_events = (
        SecurityEvent.query
        .filter_by(user_id=user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dashboard.html",
        user=user,
        transactions=transaction_rows,
        money_sent_month=float(money_sent_month or 0),
        money_received_month=float(money_received_month or 0),
        last_login=last_login.created_at if last_login else "This session",
        monthly_data=monthly_data,
        user_events=user_events,
    )


@core_bp.route("/statement")
@core_bp.route("/statement/<int:user_id>")
def statement(user_id=None):
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role == "admin" and user_id is None:
        log_event(current_app.logger, "ACCESS_DENIED", "Admin attempted to open personal statement", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    requested_user_id = user_id or user.id
    if requested_user_id != user.id and user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", f"Statement access denied for user {requested_user_id}", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    account = User.query.filter_by(id=requested_user_id, role="customer").first()
    if not account:
        return render_template(
            "error.html",
            title="Not found",
            message="The account or page you requested could not be found.",
        ), 404

    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    direction = request.args.get("direction", "all").strip()

    sender = aliased(User)
    recipient = aliased(User)
    query = (
        Transaction.query.join(sender, Transaction.from_user == sender.id)
        .join(recipient, Transaction.to_user == recipient.id)
        .filter((Transaction.from_user == requested_user_id) | (Transaction.to_user == requested_user_id))
    )
    if date_from:
        query = query.filter(func.date(Transaction.timestamp) >= date_from)
    if date_to:
        query = query.filter(func.date(Transaction.timestamp) <= date_to)
    if direction == "sent":
        query = query.filter(Transaction.from_user == requested_user_id)
    elif direction == "received":
        query = query.filter(Transaction.to_user == requested_user_id)

    transactions = (
        query.order_by(Transaction.timestamp.desc())
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

    return render_template(
        "statement.html",
        transactions=transaction_rows,
        account=account,
        requested_user_id=requested_user_id,
        filters={"date_from": date_from, "date_to": date_to, "direction": direction},
        total_sent=sum(r["amount"] for r in transaction_rows if r["from_user_id"] == requested_user_id),
        total_received=sum(r["amount"] for r in transaction_rows if r["to_user_id"] == requested_user_id),
    )


@core_bp.route("/statement/download")
@core_bp.route("/statement/<int:user_id>/download")
def statement_download(user_id=None):
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))

    requested_user_id = user_id or user.id
    if requested_user_id != user.id and user.role != "admin":
        return render_template("error.html", title="Access denied",
                               message="You do not have permission to perform that action."), 403

    account = User.query.filter_by(id=requested_user_id, role="customer").first()
    if not account:
        return render_template("error.html", title="Not found",
                               message="Account not found."), 404

    sender = aliased(User)
    recipient = aliased(User)
    rows = (
        Transaction.query
        .join(sender, Transaction.from_user == sender.id)
        .join(recipient, Transaction.to_user == recipient.id)
        .filter((Transaction.from_user == requested_user_id) | (Transaction.to_user == requested_user_id))
        .order_by(Transaction.timestamp.desc())
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

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Reference", "Description", "From", "To", "Amount", "Direction", "Status"])
    for r in rows:
        direction = "Credit" if r.to_user_id == requested_user_id else "Debit"
        writer.writerow([
            r.timestamp.strftime("%Y-%m-%d %H:%M") if r.timestamp else "",
            r.reference_code,
            r.description or "",
            r.from_user,
            r.to_user,
            f"{float(r.amount):.2f}",
            direction,
            r.status,
        ])

    output.seek(0)
    filename = f"fleuris-statement-{account.username}-{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@core_bp.route("/profile")
def profile():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))

    events = (
        SecurityEvent.query
        .filter_by(user_id=user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(10)
        .all()
    )
    last_login = (
        SecurityEvent.query
        .filter_by(user_id=user.id, event_type="LOGIN_SUCCESS")
        .order_by(SecurityEvent.created_at.desc())
        .first()
    )
    account_number = f"FLR-{user.id:04d}-{hash(user.username) % 9000 + 1000}"
    return render_template(
        "profile.html",
        user=user,
        events=events,
        last_login=last_login.created_at if last_login else None,
        account_number=account_number,
    )
