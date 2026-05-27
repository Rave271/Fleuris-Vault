import os

from flask import Blueprint, current_app, redirect, render_template, request, url_for
from sqlalchemy.orm import aliased

from ..extensions import db
from ..models import SecurityEvent, Transaction, User
from ..services.auth import generate_csrf_token, login_required, require_csrf_token
from ..services.security import log_event, read_log_lines

security_bp = Blueprint("security", __name__)


@security_bp.route("/security")
def security_center():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view security center", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    event_type = request.args.get("event_type", "").strip()
    q = request.args.get("q", "").strip()

    user_alias = aliased(User)
    query = SecurityEvent.query.outerjoin(user_alias, SecurityEvent.user_id == user_alias.id)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if q:
        query = query.filter(
            (SecurityEvent.detail.ilike(f"%{q}%"))
            | (SecurityEvent.ip_address.ilike(f"%{q}%"))
            | (user_alias.username.ilike(f"%{q}%"))
        )

    events = (
        query.order_by(SecurityEvent.created_at.desc())
        .with_entities(
            SecurityEvent.event_type,
            SecurityEvent.ip_address,
            SecurityEvent.detail,
            SecurityEvent.created_at,
            user_alias.username.label("username"),
        )
        .limit(50)
        .all()
    )
    event_rows = [
        {
            "event_type": row.event_type,
            "ip_address": row.ip_address,
            "detail": row.detail,
            "created_at": row.created_at,
            "username": row.username,
        }
        for row in events
    ]
    event_types = [
        {"event_type": row.event_type}
        for row in SecurityEvent.query.with_entities(SecurityEvent.event_type)
        .distinct()
        .order_by(SecurityEvent.event_type)
        .all()
    ]

    return render_template(
        "security.html",
        events=event_rows,
        event_types=event_types,
        selected_event_type=event_type,
        q=q,
    )


@security_bp.route("/security-log")
def security_log_view():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view security log", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    try:
        requested_lines = int(request.args.get("lines", "200"))
    except ValueError:
        requested_lines = 200

    requested_lines = max(10, min(requested_lines, 1000))
    log_path = current_app.config.get("LOG_PATH", "logs/app.json.log")
    if not os.path.isabs(log_path):
        repo_root = os.path.abspath(os.path.join(current_app.root_path, "..", ".."))
        log_path = os.path.join(repo_root, log_path)
    log_lines, log_error = read_log_lines(log_path, requested_lines)

    return render_template(
        "security_log.html",
        log_lines=log_lines,
        log_error=log_error,
        requested_lines=requested_lines,
    )


@security_bp.route("/security-demo")
def security_demo():
    user_list = User.query.order_by(User.id).all()
    user_evidence = []
    for record in user_list:
        password_hash = record.password_hash or ""
        user_evidence.append(
            {
                "id": record.id,
                "username": record.username,
                "role": record.role,
                "failed_login_count": record.failed_login_count,
                "locked_until": record.locked_until or "Not locked",
                "hash_preview": f"{password_hash[:18]}..." if password_hash else "Missing hash",
            }
        )

    alex = User.query.filter_by(username="alex").first()
    jordan = User.query.filter_by(username="jordan").first()

    demos = {
        "headers": [
            {
                "name": "Content-Security-Policy",
                "value": current_app.config.get("SECURITY_HEADERS")["Content-Security-Policy"],
                "defense": "Limits where scripts, forms, frames, and page resources can load from.",
                "owasp": "Security Misconfiguration / XSS defense-in-depth",
            },
            {
                "name": "X-Frame-Options",
                "value": current_app.config.get("SECURITY_HEADERS")["X-Frame-Options"],
                "defense": "Blocks clickjacking by preventing the app from being embedded in iframes.",
                "owasp": "Security Misconfiguration",
            },
            {
                "name": "X-Content-Type-Options",
                "value": current_app.config.get("SECURITY_HEADERS")["X-Content-Type-Options"],
                "defense": "Stops browsers from guessing unsafe content types.",
                "owasp": "Security Misconfiguration",
            },
            {
                "name": "Referrer-Policy",
                "value": current_app.config.get("SECURITY_HEADERS")["Referrer-Policy"],
                "defense": "Reduces accidental leakage of sensitive URLs to other origins.",
                "owasp": "Sensitive Data Exposure support control",
            },
        ],
        "sql_injection": {
            "attack": "' OR '1'='1",
            "old_risk": "String-built SQL could treat this payload as query logic.",
            "current_query": "SELECT * FROM users WHERE username=?",
            "result": "Rejected as ordinary username text, not executed as SQL.",
            "owasp": "Injection",
        },
        "authentication": {
            "lockout_limit": current_app.config.get("MAX_LOGIN_ATTEMPTS"),
            "lockout_minutes": current_app.config.get("LOCKOUT_MINUTES"),
            "users": user_evidence,
            "result": "Passwords are hashed, failed logins are counted, and accounts can be temporarily locked.",
            "owasp": "Identification and Authentication Failures",
        },
        "access_control": [
            {
                "case": f"Alex opens /statement/{alex.id if alex else 1}",
                "result": "Allowed",
                "reason": "The requested account belongs to the signed-in customer.",
            },
            {
                "case": f"Alex opens /statement/{jordan.id if jordan else 2}",
                "result": "Blocked with 403 Forbidden",
                "reason": "A customer cannot read another customer's statement.",
            },
            {
                "case": "Admin opens /statement",
                "result": "Blocked with 403 Forbidden",
                "reason": "Admin is an operational role, not a customer bank account.",
            },
            {
                "case": f"Admin opens /statement/{jordan.id if jordan else 2}",
                "result": "Allowed",
                "reason": "Admin role is permitted to review customer accounts.",
            },
        ],
        "csrf": {
            "attack": "POST /transfer without csrf_token",
            "result": "Rejected with 400 Bad Request and logged as CSRF_BLOCKED.",
            "defense": "The transfer form includes a session-bound token that must match on submit.",
            "owasp": "Broken Access Control / CSRF defense",
        },
    }
    team_demo_notes = [
        "SQL injection attempts are treated as normal input through parameterized queries.",
        "Transfer requests require a session-bound CSRF token.",
        "Access denied events are recorded for admin review.",
    ]
    return render_template("security_demo.html", demos=demos, team_demo_notes=team_demo_notes)


@security_bp.route("/demo-controls", methods=["GET", "POST"])
def demo_controls():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view demo controls", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    if request.method == "POST":
        require_csrf_token(current_app.logger, request.form.get("csrf_token"))

        action = request.form.get("action")
        if action == "seed_transactions":
            from ..services.transfer import make_reference_code
            from ..models import Transaction
            alex = User.query.filter_by(username="alex").first()
            morgan = User.query.filter_by(username="morgan").first()
            casey = User.query.filter_by(username="casey").first()
            if alex and morgan and casey:
                samples = [
                    (alex.id, morgan.id, 42.75, "Lunch reimbursement"),
                    (casey.id, alex.id, 125.00, "Project payment"),
                    (morgan.id, casey.id, 18.50, "Shared cab"),
                ]
                for from_id, to_id, amount, description in samples:
                    db.session.add(
                        Transaction(
                            from_user=from_id,
                            to_user=to_id,
                            amount=amount,
                            reference_code=make_reference_code(),
                            status="completed",
                            description=description,
                        )
                    )
                db.session.commit()
                log_event(current_app.logger, "DEMO_SEEDED", "Seeded sample transactions", user.id)
        elif action == "lock_test_user":
            from datetime import datetime, timedelta

            morgan = User.query.filter_by(username="morgan", role="customer").first()
            if morgan:
                morgan.failed_login_count = current_app.config.get("MAX_LOGIN_ATTEMPTS")
                morgan.locked_until = datetime.utcnow() + timedelta(
                    minutes=current_app.config.get("LOCKOUT_MINUTES")
                )
                db.session.commit()
                log_event(current_app.logger, "DEMO_LOCKED_USER", "Locked morgan for demo", user.id)
        elif action == "clear_events":
            SecurityEvent.query.delete()
            db.session.commit()
            log_event(current_app.logger, "DEMO_CLEARED_EVENTS", "Cleared DB audit events", user.id)
        else:
            return render_template(
                "error.html",
                title="Request blocked",
                message="The request could not be completed. Please refresh and try again.",
            ), 400
        return redirect(url_for("security.demo_controls"))

    counts = {
        "customers": User.query.filter_by(role="customer").count(),
        "transactions": Transaction.query.count(),
        "events": SecurityEvent.query.count(),
        "locked": User.query.filter_by(role="customer").filter(User.locked_until.isnot(None)).count(),
    }
    return render_template("demo_controls.html", counts=counts, csrf_token=generate_csrf_token())
