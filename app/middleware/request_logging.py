import secrets
import time
from flask import g, request


def register_request_logging(app, logger):
    @app.before_request
    def start_timer():
        g.request_start = time.time()
        g.request_id = request.headers.get("X-Request-ID") or secrets.token_hex(8)

    @app.after_request
    def log_request(response):
        duration_ms = int((time.time() - g.get("request_start", time.time())) * 1000)
        user = getattr(g, "current_user", None)
        event = {
            "event_type": "http_request",
            "username": getattr(user, "username", None) if user else None,
            "user_id": getattr(user, "id", None) if user else None,
            "endpoint": request.path,
            "method": request.method,
            "status_code": response.status_code,
            "response_time_ms": duration_ms,
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "request_id": g.request_id,
        }
        logger.info("request", extra={"event": event})
        response.headers["X-Request-ID"] = g.request_id
        return response

    return app
