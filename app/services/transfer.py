from decimal import Decimal, InvalidOperation

from ..extensions import db
from ..models import Transaction, User
from .security import log_event


def parse_money(raw_amount):
    try:
        return Decimal(raw_amount).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        return Decimal("0.00")


def make_reference_code():
    from datetime import datetime
    import secrets

    return f"FLR-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"


def create_transfer(logger, user, recipient_id, amount, description):
    recipient = User.query.filter_by(id=recipient_id).first()
    if not recipient:
        return None, "Recipient account was not found."
    if recipient.id == user.id:
        return None, "Transfers to your own account are not allowed."
    if amount <= 0 or amount > Decimal("5000"):
        return None, "Enter a transfer amount between $0.01 and $5,000.00."
    if Decimal(user.balance) < amount:
        return None, "Insufficient funds."

    user.balance = Decimal(user.balance) - amount
    recipient.balance = Decimal(recipient.balance) + amount
    reference_code = make_reference_code()
    transaction = Transaction(
        from_user=user.id,
        to_user=recipient.id,
        amount=amount,
        reference_code=reference_code,
        status="completed",
        description=description or "Customer transfer",
    )
    db.session.add(transaction)
    db.session.commit()
    log_event(
        logger,
        "TRANSFER_CREATED",
        f"Sent ${amount:.2f} to account {recipient.id} reference {reference_code}",
        user.id,
        username=user.username,
    )
    return transaction, None
