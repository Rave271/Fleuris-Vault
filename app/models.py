from datetime import datetime

from .extensions import db


class DictMixin:
    def __getitem__(self, key):
        return getattr(self, key)


class User(DictMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Numeric(12, 2), default=0)
    role = db.Column(db.String(20), default="customer")
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)


class Transaction(DictMixin, db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    from_user = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    reference_code = db.Column(db.String(40), nullable=False)
    status = db.Column(db.String(20), default="completed")
    description = db.Column(db.String(160), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class SecurityEvent(DictMixin, db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    detail = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AnalyticsEndpointPopularity(DictMixin, db.Model):
    __tablename__ = "analytics_endpoint_popularity"

    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(255), nullable=False)
    total_hits = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class AnalyticsLoginSummary(DictMixin, db.Model):
    __tablename__ = "analytics_login_summary"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    total_count = db.Column(db.Integer, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class AnalyticsResponseTime(DictMixin, db.Model):
    __tablename__ = "analytics_response_times"

    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(255), nullable=False)
    avg_response_ms = db.Column(db.Float, nullable=False)
    p95_response_ms = db.Column(db.Float, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class AnalyticsUserActivity(DictMixin, db.Model):
    __tablename__ = "analytics_user_activity"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, nullable=True)
    total_requests = db.Column(db.Integer, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)


class AnalyticsTrafficRun(DictMixin, db.Model):
    __tablename__ = "analytics_traffic_runs"

    id = db.Column(db.Integer, primary_key=True)
    scenario = db.Column(db.String(64), nullable=False)
    total_events = db.Column(db.Integer, nullable=False)
    success_events = db.Column(db.Integer, nullable=False)
    failed_events = db.Column(db.Integer, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
