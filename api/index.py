"""
NetDecoy - Vercel Serverless Function Entrypoint
Routes all incoming serverless requests to the centralized NetDecoy Flask application.
"""
import os
import sys
import traceback

# Ensure project root is on sys.path so 'backend' and 'intelligence' can be resolved
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

cwd = os.getcwd()
if cwd not in sys.path:
    sys.path.insert(0, cwd)

try:
    from backend.app import app
except Exception as e:
    from flask import Flask, jsonify
    err_trace = traceback.format_exc()
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path):
        return jsonify({
            "status": "error",
            "error_type": "startup_import_failure",
            "message": str(e),
            "traceback": err_trace.splitlines(),
            "sys_path": sys.path,
            "cwd": cwd,
            "project_root": PROJECT_ROOT
        }), 500

__all__ = ["app"]

if __name__ == "__main__":
    app.run()
