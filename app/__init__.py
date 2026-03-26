from __future__ import annotations

from flask import Flask

from app.admin.routes import admin_bp
from app.auth.routes import auth_bp
from app.config import Config
from app.errors import register_error_handlers
from app.extensions import db
from app.resource.routes import resource_bp
from app.security.tokens import initialize_keys
from app.ui.routes import ui_bp


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    if config_overrides:
        app.config.update(config_overrides)

    db.init_app(app)
    app.register_blueprint(ui_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(resource_bp)
    register_error_handlers(app)

    with app.app_context():
        initialize_keys(app.config)
        db.create_all()

    return app
