from __future__ import annotations

from flask import jsonify


def register_error_handlers(app) -> None:
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "bad_request", "message": str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "not_found", "message": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "internal_server_error", "message": "Unexpected server error"}), 500
