"""
VulnHawk Web Interface

Provides a modern, secure web UI for the scanner.
"""

from flask import Blueprint

web_bp = Blueprint('web', __name__)

from app.web import routes
