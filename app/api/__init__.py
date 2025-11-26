"""
VulnHawk REST API

Provides programmatic access to scanner functionality.
"""

from flask import Blueprint

api_bp = Blueprint('api', __name__)

from app.api import routes
