from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models import User


def seed_users():
    seed_data = [
        ("alex", "pass", 1000.0, "customer"),
        ("jordan", "pass", 750.0, "customer"),
        ("taylor", "pass", 500.0, "customer"),
        ("morgan", "pass", 300.0, "customer"),
        ("casey", "pass", 200.0, "customer"),
        ("raghav", "123", 2500.0, "admin"),
    ]
    for username, password, balance, role in seed_data:
        existing = User.query.filter_by(username=username).first()
        if existing:
            continue
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            balance=balance,
            role=role,
        )
        db.session.add(user)
    db.session.commit()
