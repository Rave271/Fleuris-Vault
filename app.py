from datetime import datetime, timedelta
import base64
import io
import logging
import os
import secrets
import sqlite3

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
import pyotp
import qrcode
from qrcode.image.svg import SvgImage
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get("AEGIS_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

BASE_DIR = os.path.dirname(__file__)
DATABASE = os.path.join(BASE_DIR, "bank.db")
SECURITY_LOG = os.path.join(BASE_DIR, "security.log")
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}
TEAM_DEMO_NOTES = [
    "SQL injection attempts are treated as normal input through parameterized queries.",
    "Transfer requests require a session-bound CSRF token.",
    "Access denied events are recorded for admin review.",
]

# Security logging to file + DB for audit review.
logging.basicConfig(
    filename=SECURITY_LOG,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.after_request
def add_security_headers(response):
    # Security headers: CSP, clickjacking, MIME sniffing, referrer policy.
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


def column_exists(table, column):
    rows = get_db().execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def ensure_column(table, column, definition):
    if not column_exists(table, column):
        get_db().execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def log_event(event_type, detail, user_id=None):
    # Audit logging to file + database.
    logging.info("%s user=%s ip=%s %s", event_type, user_id, request.remote_addr, detail)
    get_db().execute(
        "INSERT INTO security_events (event_type, user_id, ip_address, detail) VALUES (?, ?, ?, ?)",
        (event_type, user_id, request.remote_addr, detail),
    )
    get_db().commit()


def read_security_log(max_lines=200):
    try:
        with open(SECURITY_LOG, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return [], "Security log file not found yet."
    except OSError:
        return [], "Unable to read security log file."

    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return [line.rstrip("\n") for line in lines], None


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                balance REAL DEFAULT 0
            )"""
        )
        ensure_column("users", "password_hash", "TEXT")
        ensure_column("users", "role", "TEXT DEFAULT 'customer'")
        ensure_column("users", "failed_login_count", "INTEGER DEFAULT 0")
        ensure_column("users", "locked_until", "TEXT")
        ensure_column("users", "totp_secret", "TEXT")

        cursor.execute(
            """CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                from_user INTEGER,
                to_user INTEGER,
                amount REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(from_user) REFERENCES users(id),
                FOREIGN KEY(to_user) REFERENCES users(id)
            )"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                ip_address TEXT,
                detail TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )

        seed_users = [
            ("mehak", "pass", 1000.0, "customer"),
            ("jashanjot", "pass", 750.0, "customer"),
            ("jashan", "pass", 500.0, "customer"),
            ("aryan", "pass", 300.0, "customer"),
            ("vanshika", "pass", 200.0, "customer"),
            ("raghav", "Admin@123", 2500.0, "admin"),
        ]
        for username, password, balance, role in seed_users:
            # Password hashing: no plaintext storage.
            cursor.execute(
                """INSERT OR IGNORE INTO users
                   (username, password_hash, balance, role)
                   VALUES (?, ?, ?, ?)""",
                (username, generate_password_hash(password), balance, role),
            )

        if column_exists("users", "password"):
            rows = cursor.execute(
                "SELECT id, password FROM users WHERE password_hash IS NULL"
            ).fetchall()
            for row in rows:
                cursor.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (generate_password_hash(row["password"]), row["id"]),
                )
            cursor.execute("UPDATE users SET password=NULL")
        db.commit()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute(
        "SELECT id, username, balance, role FROM users WHERE id=?",
        (session["user_id"],),
    ).fetchone()


def login_required():
    user = current_user()
    if not user:
        return None
    return user


def require_csrf_token():
    # CSRF defense: session-bound token required for state-changing actions.
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        log_event("CSRF_BLOCKED", "Invalid or missing CSRF token", session.get("user_id"))
        abort(400)


def csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


@app.context_processor
def inject_globals():
    return {"brand_name": "Fleuris Vault", "current_user": current_user()}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/security-demo")
def security_demo():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, failed_login_count, locked_until, password_hash FROM users ORDER BY id"
    ).fetchall()
    user_evidence = []
    for user in users:
        password_hash = user["password_hash"] or ""
        user_evidence.append(
            {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "failed_login_count": user["failed_login_count"],
                "locked_until": user["locked_until"] or "Not locked",
                "hash_preview": f"{password_hash[:18]}..." if password_hash else "Missing hash",
            }
        )

    mehak = db.execute("SELECT id FROM users WHERE username=?", ("mehak",)).fetchone()
    jashanjot = db.execute("SELECT id FROM users WHERE username=?", ("jashanjot",)).fetchone()

    demos = {
        "headers": [
            {
                "name": "Content-Security-Policy",
                "value": SECURITY_HEADERS["Content-Security-Policy"],
                "defense": "Limits where scripts, forms, frames, and page resources can load from.",
                "owasp": "Security Misconfiguration / XSS defense-in-depth",
            },
            {
                "name": "X-Frame-Options",
                "value": SECURITY_HEADERS["X-Frame-Options"],
                "defense": "Blocks clickjacking by preventing the app from being embedded in iframes.",
                "owasp": "Security Misconfiguration",
            },
            {
                "name": "X-Content-Type-Options",
                "value": SECURITY_HEADERS["X-Content-Type-Options"],
                "defense": "Stops browsers from guessing unsafe content types.",
                "owasp": "Security Misconfiguration",
            },
            {
                "name": "Referrer-Policy",
                "value": SECURITY_HEADERS["Referrer-Policy"],
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
            "lockout_limit": MAX_LOGIN_ATTEMPTS,
            "lockout_minutes": LOCKOUT_MINUTES,
            "users": user_evidence,
            "result": "Passwords are hashed, failed logins are counted, and accounts can be temporarily locked.",
            "owasp": "Identification and Authentication Failures",
        },
        "access_control": [
            {
                "case": f"Mehak opens /statement/{mehak['id'] if mehak else 1}",
                "result": "Allowed",
                "reason": "The requested account belongs to the signed-in customer.",
            },
            {
                "case": f"Mehak opens /statement/{jashanjot['id'] if jashanjot else 2}",
                "result": "Blocked with 403 Forbidden",
                "reason": "A customer cannot read another customer's statement.",
            },
            {
                "case": "Admin opens /statement",
                "result": "Blocked with 403 Forbidden",
                "reason": "Admin is an operational role, not a customer bank account.",
            },
            {
                "case": f"Admin opens /statement/{jashanjot['id'] if jashanjot else 2}",
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
    return render_template("security_demo.html", demos=demos, team_demo_notes=TEAM_DEMO_NOTES)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    def record_failed_login(user, username, event_type, detail):
        failed_count = user["failed_login_count"] + 1
        locked_until = None
        if failed_count >= MAX_LOGIN_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        db.execute(
            "UPDATE users SET failed_login_count=?, locked_until=? WHERE id=?",
            (failed_count, locked_until, user["id"]),
        )
        db.commit()
        log_event(event_type, detail, user["id"])

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        mfa_code = request.form.get("mfa_code", "").strip()
        db = get_db()
        user = db.execute(
            # SQL injection defense: parameterized query.
            "SELECT * FROM users WHERE username=?",
            (username,),
        ).fetchone()

        if user and user["locked_until"]:
            # Brute-force defense: temporary account lockout.
            locked_until = datetime.fromisoformat(user["locked_until"])
            if locked_until > datetime.utcnow():
                log_event("LOGIN_LOCKED", f"Locked account login attempt for {username}", user["id"])
                return render_template("login.html", error="Account is temporarily locked. Try again later.")

        if user and check_password_hash(user["password_hash"], password):
            if user["totp_secret"]:
                totp = pyotp.TOTP(user["totp_secret"])
                if not totp.verify(mfa_code, valid_window=1):
                    record_failed_login(
                        user,
                        username,
                        "MFA_FAILED",
                        f"Invalid MFA code for {username}",
                    )
                    error = "Invalid MFA code."
                    return render_template("login.html", error=error)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            db.execute(
                "UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id=?",
                (user["id"],),
            )
            db.commit()
            log_event("LOGIN_SUCCESS", f"{username} signed in", user["id"])
            return redirect(url_for("dashboard"))

        if user:
            record_failed_login(
                user,
                username,
                "LOGIN_FAILED",
                f"Failed login for {username}",
            )
        else:
            log_event("LOGIN_FAILED", f"Unknown username {username}")

        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    user = login_required()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    user_record = db.execute(
        "SELECT id, username, role, totp_secret FROM users WHERE id=?",
        (user["id"],),
    ).fetchone()
    secret = user_record["totp_secret"]
    if request.method == "POST":
        secret = pyotp.random_base32()
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user_record["id"]))
        db.commit()
        log_event("MFA_ENABLED", "MFA secret generated", user_record["id"])
    qr_data = None
    if secret:
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_record["username"],
            issuer_name="Fleuris Vault",
        )
        qr_image = qrcode.make(provisioning_uri, image_factory=SvgImage)
        buffer = io.BytesIO()
        qr_image.save(buffer)
        qr_data = base64.b64encode(buffer.getvalue()).decode("ascii")
    return render_template("mfa_setup.html", secret=secret, user=user_record, qr_data=qr_data)


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        log_event("LOGOUT", "User signed out", user_id)
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] == "admin":
        db = get_db()
        customer_count = db.execute("SELECT COUNT(*) FROM users WHERE role='customer'").fetchone()[0]
        event_count = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        locked_count = db.execute(
            "SELECT COUNT(*) FROM users WHERE role='customer' AND locked_until IS NOT NULL"
        ).fetchone()[0]
        recent_events = db.execute(
            """SELECT event_type, detail, created_at
               FROM security_events
               ORDER BY created_at DESC
               LIMIT 5"""
        ).fetchall()
        return render_template(
            "admin_dashboard.html",
            user=user,
            customer_count=customer_count,
            event_count=event_count,
            locked_count=locked_count,
            recent_events=recent_events,
        )

    db = get_db()
    transactions = db.execute(
        """SELECT t.id, u1.username AS from_user, u2.username AS to_user, t.amount, t.timestamp
           FROM transactions t
           JOIN users u1 ON t.from_user = u1.id
           JOIN users u2 ON t.to_user = u2.id
           WHERE t.from_user=? OR t.to_user=?
           ORDER BY t.timestamp DESC
           LIMIT 5""",
        (user["id"], user["id"]),
    ).fetchall()
    return render_template("dashboard.html", user=user, transactions=transactions)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] == "admin":
        log_event("ACCESS_DENIED", "Admin attempted to open customer transfer flow", user["id"])
        abort(403)

    db = get_db()
    message = None
    message_type = "info"

    if request.method == "POST":
        require_csrf_token()
        to_account = request.form.get("to_account", "").strip()
        raw_amount = request.form.get("amount", "").strip()

        try:
            amount = round(float(raw_amount), 2)
        except ValueError:
            amount = 0

        recipient = db.execute(
            "SELECT id, username FROM users WHERE id=?",
            (to_account,),
        ).fetchone()

        if not recipient:
            message = "Recipient account was not found."
            message_type = "error"
        elif recipient["id"] == user["id"]:
            message = "Transfers to your own account are not allowed."
            message_type = "error"
        elif amount <= 0 or amount > 5000:
            message = "Enter a transfer amount between $0.01 and $5,000.00."
            message_type = "error"
        elif user["balance"] < amount:
            message = "Insufficient funds."
            message_type = "error"
        else:
            db.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, user["id"]))
            db.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, recipient["id"]))
            db.execute(
                "INSERT INTO transactions (from_user, to_user, amount) VALUES (?, ?, ?)",
                (user["id"], recipient["id"], amount),
            )
            db.commit()
            log_event(
                "TRANSFER_CREATED",
                f"Sent ${amount:.2f} to account {recipient['id']}",
                user["id"],
            )
            message = f"Transfer to {recipient['username']} completed."
            message_type = "success"

    recipients = db.execute(
        "SELECT id, username FROM users WHERE id != ? AND role='customer' ORDER BY username",
        (user["id"],),
    ).fetchall()
    return render_template(
        "transfer.html",
        user=current_user(),
        recipients=recipients,
        message=message,
        message_type=message_type,
        csrf_token=csrf_token(),
    )


@app.route("/statement")
@app.route("/statement/<int:user_id>")
def statement(user_id=None):
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] == "admin" and user_id is None:
        # Access control: admins cannot view their own statements.
        log_event("ACCESS_DENIED", "Admin attempted to open personal statement", user["id"])
        abort(403)

    requested_user_id = user_id or user["id"]
    if requested_user_id != user["id"] and user["role"] != "admin":
        # Access control: customers cannot view other customers' statements.
        log_event("ACCESS_DENIED", f"Statement access denied for user {requested_user_id}", user["id"])
        abort(403)

    db = get_db()
    account = db.execute(
        "SELECT id, username FROM users WHERE id=? AND role='customer'",
        (requested_user_id,),
    ).fetchone()
    if not account:
        abort(404)

    transactions = db.execute(
        """SELECT t.id, u1.username AS from_user, u2.username AS to_user, t.amount, t.timestamp
           FROM transactions t
           JOIN users u1 ON t.from_user = u1.id
           JOIN users u2 ON t.to_user = u2.id
           WHERE t.from_user=? OR t.to_user=?
           ORDER BY t.timestamp DESC""",
        (requested_user_id, requested_user_id),
    ).fetchall()
    return render_template("statement.html", transactions=transactions, account=account)


@app.route("/users")
def users():
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] != "admin":
        log_event("ACCESS_DENIED", "Non-admin attempted to view users", user["id"])
        abort(403)

    db = get_db()
    all_users = db.execute(
        """SELECT id, username, balance, role, failed_login_count, locked_until
           FROM users
           WHERE role='customer'
           ORDER BY id"""
    ).fetchall()
    return render_template("users.html", users=all_users)


@app.route("/security")
def security_center():
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] != "admin":
        log_event("ACCESS_DENIED", "Non-admin attempted to view security center", user["id"])
        abort(403)

    events = get_db().execute(
        """SELECT e.event_type, e.ip_address, e.detail, e.created_at, u.username
           FROM security_events e
           LEFT JOIN users u ON e.user_id = u.id
           ORDER BY e.created_at DESC
           LIMIT 30"""
    ).fetchall()
    return render_template("security.html", events=events)


@app.route("/security-log")
def security_log_view():
    user = login_required()
    if not user:
        return redirect(url_for("login"))
    if user["role"] != "admin":
        log_event("ACCESS_DENIED", "Non-admin attempted to view security log", user["id"])
        abort(403)

    try:
        requested_lines = int(request.args.get("lines", "200"))
    except ValueError:
        requested_lines = 200

    requested_lines = max(10, min(requested_lines, 1000))
    log_lines, log_error = read_security_log(requested_lines)
    return render_template(
        "security_log.html",
        log_lines=log_lines,
        log_error=log_error,
        requested_lines=requested_lines,
    )


init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port)
