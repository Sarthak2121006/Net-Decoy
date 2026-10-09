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

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from backend.database.db import init_db
from backend.routes import register_routes

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netdecoy.backend")

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
TRAPS_DIR = os.path.join(PROJECT_ROOT, "traps")

def create_app(test_config=None):
    """Application Factory for NetDecoy Flask Backend."""
    app = Flask(__name__)

    # Enable CORS across all origins for hackathon frontend integration
    CORS(app, resources={r"/*": {"origins": "*"}})

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
        # If requested explicitly for HTML via browser, we can serve dashboard or provide JSON API discovery
        if request.headers.get("Accept") and "text/html" in request.headers.get("Accept") and "application/json" not in request.headers.get("Accept"):
            return send_from_directory(FRONTEND_DIR, "dashboard.html")
        return jsonify({
            "service": "NetDecoy Honeypot Backend",
            "status": "online",
            "version": "1.0.0",
            "dashboard_url": "/dashboard",
            "traps_url": "/traps",
            "demo_runner": "/demo",
            "docs": "/shared/api_contract.md"
        }), 200

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "database": "connected"
        }), 200

    # Frontend Dashboard Web Routes
    @app.route("/dashboard", methods=["GET"])
    @app.route("/dashboard.html", methods=["GET"])
    def serve_dashboard():
        return send_from_directory(FRONTEND_DIR, "dashboard.html")

    @app.route("/dashboard.css", methods=["GET"])
    def serve_dashboard_css():
        return send_from_directory(FRONTEND_DIR, "dashboard.css")

    @app.route("/dashboard.js", methods=["GET"])
    def serve_dashboard_js():
        return send_from_directory(FRONTEND_DIR, "dashboard.js")

    @app.route("/frontend/<path:filename>", methods=["GET"])
    def serve_frontend_assets(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    # Honeypot Deception Traps Web Routes
    @app.route("/traps", methods=["GET"])
    @app.route("/traps/", methods=["GET"])
    @app.route("/traps/index.html", methods=["GET"])
    def serve_traps_hub():
        return send_from_directory(TRAPS_DIR, "index.html")

    @app.route("/traps/<path:filename>", methods=["GET"])
    def serve_traps_files(filename):
        return send_from_directory(TRAPS_DIR, filename)

    # Shortcut Traps URLs
    @app.route("/login", methods=["GET"])
    def serve_login_trap():
        return send_from_directory(TRAPS_DIR, "login.html")

    @app.route("/admin", methods=["GET"])
    def serve_admin_trap():
        return send_from_directory(TRAPS_DIR, "admin.html")

    @app.route("/backup", methods=["GET"])
    def serve_backup_trap():
        return send_from_directory(TRAPS_DIR, "backup.html")

    @app.route("/database", methods=["GET"])
    def serve_database_trap():
        return send_from_directory(TRAPS_DIR, "database.html")

    @app.route("/api-explorer", methods=["GET"])
    def serve_api_explorer_trap():
        return send_from_directory(TRAPS_DIR, "api.html")

    @app.route("/search", methods=["GET"])
    def serve_search_trap():
        return send_from_directory(TRAPS_DIR, "search.html")

    @app.route("/demo", methods=["GET"])
    def serve_demo_runner():
        return send_from_directory(TRAPS_DIR, "demo_runner.html")

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
