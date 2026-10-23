"""
NetDecoy - Primary Web Application Entrypoint for Vercel / WSGI
"""
import os
import sys

# Ensure root directory is on sys.path
root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.app import app

__all__ = ["app"]

if __name__ == "__main__":
    app.run()
