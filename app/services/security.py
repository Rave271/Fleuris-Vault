from datetime import datetime

from flask import g, has_request_context, request

from ..extensions import db
from ..models import SecurityEvent


def log_event(logger, event_type, detail, user_id=None, username=None, request_id=None):
    ip_address = None
    endpoint = None
    method = None
    if has_request_context():
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        endpoint = request.path
        method = request.method
        if request_id is None:
            request_id = getattr(g, "request_id", None)
    security_event = SecurityEvent(
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        detail=detail,
    )
    db.session.add(security_event)
    db.session.commit()

    event = {
        "event_type": event_type,
        "username": username,
        "user_id": user_id,
        "endpoint": endpoint,
        "method": method,
        "status_code": None,
        "response_time_ms": None,
        "ip_address": ip_address,
        "request_id": request_id,
        "detail": detail,
    }
    logger.info(event_type.lower(), extra={"event": event})


def read_log_lines(log_path, max_lines=200):
    try:
        lines = []
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                lines.append(line)
                if len(lines) > max_lines:
                    lines.pop(0)
    except FileNotFoundError:
        return [], "Log file not found yet."
    except OSError:
        return [], "Unable to read log file."

    return [line.rstrip("\n") for line in lines], None
