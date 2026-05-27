from flask import Blueprint, current_app, redirect, render_template, request, url_for, flash

from ..models import User
from ..services.auth import generate_csrf_token, login_required, require_csrf_token
from ..services.security import log_event
from ..services.transfer import create_transfer, parse_money

transfer_bp = Blueprint("transfer", __name__)


@transfer_bp.route("/transfer", methods=["GET", "POST"])
def transfer():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role == "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Admin attempted to open customer transfer flow", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    message = None
    message_type = "info"
    review = None

    if request.method == "POST":
        require_csrf_token(current_app.logger, request.form.get("csrf_token"))

        action = request.form.get("action", "review")
        to_account = request.form.get("to_account", "").strip()
        raw_amount = request.form.get("amount", "").strip()
        description = request.form.get("description", "").strip()[:120]
        amount = parse_money(raw_amount)
        try:
            account_id = int(to_account)
        except ValueError:
            account_id = None

        recipient = User.query.filter_by(id=account_id).first() if account_id else None

        if not recipient:
            message = "Recipient account was not found."
            message_type = "error"
        elif recipient.id == user.id:
            message = "Transfers to your own account are not allowed."
            message_type = "error"
        elif amount <= 0 or amount > 5000:
            message = "Enter a transfer amount between $0.01 and $5,000.00."
            message_type = "error"
        elif float(user.balance) < float(amount):
            message = "Insufficient funds."
            message_type = "error"
        elif action == "review":
            review = {
                "to_account": recipient.id,
                "recipient": recipient.username,
                "amount": float(amount),
                "description": description,
                "balance_after": round(float(user.balance) - float(amount), 2),
            }
        else:
            transaction, error = create_transfer(current_app.logger, user, recipient.id, amount, description)
            if error:
                message = error
                message_type = "error"
            else:
                flash(
                    f"Transfer to {recipient.username} completed. Reference {transaction.reference_code}.",
                    "success",
                )
                return redirect(url_for("core.statement"))

    recipients = User.query.filter(User.id != user.id, User.role == "customer").order_by(User.username).all()
    return render_template(
        "transfer.html",
        user=user,
        recipients=recipients,
        message=message,
        message_type=message_type,
        review=review,
        csrf_token=generate_csrf_token(),
    )
