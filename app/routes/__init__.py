from .admin import admin_bp
from .analytics import analytics_bp
from .auth import auth_bp
from .core import core_bp
from .security import security_bp
from .traffic import traffic_bp
from .transfer import transfer_bp


def register_blueprints(app):
    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(transfer_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(traffic_bp)
