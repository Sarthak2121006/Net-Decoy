import os
import sys

# Ensure project root is on sys.path so backend and intelligence modules can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app

# Vercel WSGI entry point
