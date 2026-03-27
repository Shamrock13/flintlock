# Vercel WSGI entrypoint for Cashel demo.
# Vercel's Python runtime imports this file and looks for `app`.
# We add src/ to sys.path so the cashel package resolves correctly.
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cashel.web import app
