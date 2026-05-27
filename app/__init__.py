import os
from datetime import timedelta

from flask import Flask, render_template

from .config import Config
from .extensions import db
from .logging.json_logger import configure_json_logger
from .middleware.request_logging import register_request_logging
from .routes import register_blueprints
from .services.seed import seed_users

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


def create_app(config_class=Config):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )

    app.config.from_object(config_class)

    # Force debug visibility
    app.config["DEBUG"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["TRAP_HTTP_EXCEPTIONS"] = True
    app.config["TRAP_BAD_REQUEST_ERRORS"] = True

    # Ensure secret key exists
    app.config["SECRET_KEY"] = (
        os.getenv("SECRET_KEY")
        or app.config.get("SECRET_KEY")
        or "dev-secret-key"
    )

    app.config["SECURITY_HEADERS"] = SECURITY_HEADERS
    app.config["MAX_LOGIN_ATTEMPTS"] = 5
    app.config["LOCKOUT_MINUTES"] = 10

    app.config["LOG_PATH"] = os.path.join(
        app.config["LOG_DIR"],
        "app.json.log"
    )

    app.permanent_session_lifetime = timedelta(
        seconds=app.config["PERMANENT_SESSION_LIFETIME"]
    )

    db.init_app(app)

    logger = configure_json_logger(app.config["LOG_DIR"])

    app.logger.handlers = logger.handlers
    app.logger.setLevel(logger.level)

    register_request_logging(app, logger)

    @app.after_request
    def add_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    @app.context_processor
    def inject_globals():
        from .services.auth import current_user as get_current_user
        return {
            "brand_name": "Fleuris Vault",
            "current_user": get_current_user(),
        }

    register_blueprints(app)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html",
            title="Request blocked",
            message="The request could not be completed. Please refresh and try again.",
        ), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template(
            "error.html",
            title="Not found",
            message="The account or page you requested could not be found.",
        ), 404

    # IMPORTANT:
    # Leave 500 handler DISABLED during debugging
    # so Flask shows the real traceback.

    # @app.errorhandler(500)
    # def server_error(error):
    #     return render_template(
    #         "error.html",
    #         title="Something went wrong",
    #         message="The app hit an unexpected problem. Please try again.",
    #     ), 500

    with app.app_context():
        db.create_all()
        seed_users()

    return app