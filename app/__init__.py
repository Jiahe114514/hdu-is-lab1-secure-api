"""Application factory."""

from __future__ import annotations

from flask import Flask, jsonify, request

from . import db
from .config import Config
from .routes.auth import auth_bp
from .routes.data import data_bp

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)
    app.url_map.strict_slashes = False

    db.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(data_bp)

    @app.after_request
    def harden_response(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        return response

    @app.errorhandler(400)
    def bad_request(error):  # pragma: no cover - exercised via routing errors
        return jsonify({"error": "bad_request", "message": getattr(error, "description", "Bad request.")}), 400

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "not_found", "message": f"No route for {request.path}."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "method_not_allowed", "message": "HTTP method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(_error):  # pragma: no cover - defensive
        return jsonify({"error": "internal_error", "message": "Unexpected server error."}), 500

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app
