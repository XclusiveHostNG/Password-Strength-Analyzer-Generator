"""Flask application factory for the password security toolkit."""
from __future__ import annotations

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me"

    from .routes import bp

    app.register_blueprint(bp)
    return app


__all__ = ["create_app"]
