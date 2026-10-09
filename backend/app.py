"""
NetDecoy Central Backend Application
Connects Trap Pages -> Event Collector -> Intelligence Engine -> Dashboard
"""
import os
import sys
import logging

# Ensure project root is in sys.path when running 'python backend/app.py' directly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify
from flask_cors import CORS
from backend.database.db import init_db
from backend.routes import register_routes

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netdecoy.backend")

def create_app(test_config=None):
    """Application Factory for NetDecoy Flask Backend."""
    app = Flask(__name__)

    # Enable CORS across all origins for hackathon frontend integration
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Configure application
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "netdecoy-super-secret-key-2026"),
        JSON_SORT_KEYS=False
    )

    if test_config:
        app.config.update(test_config)

    # Initialize Database Tables
    with app.app_context():
        init_db()
        logger.info("NetDecoy database initialized successfully.")

    # Register API Endpoints
    register_routes(app)

    # Root & Health Endpoints
    @app.route("/", methods=["GET"])
    def root():
        return jsonify({
            "service": "NetDecoy Honeypot Backend",
            "status": "online",
            "version": "1.0.0",
            "docs": "/shared/api_contract.md"
        }), 200

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "database": "connected"
        }), 200

    # Error Handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting NetDecoy backend server on http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
