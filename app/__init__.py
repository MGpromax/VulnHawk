"""
VulnHawk - Advanced Web Application Vulnerability Scanner
Author: Manoj Gowda
Version: 1.0.0

A production-ready, secure vulnerability scanner with:
- Async scanning engine for high performance
- OWASP Top 10 coverage
- CVSS v3.1 scoring
- Professional PDF/HTML reports
- Real-time WebSocket updates
"""

import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_socketio import SocketIO

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
login_manager = LoginManager()
socketio = SocketIO()

# Configure logging - SECURITY: Don't log sensitive data
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """
    Application factory pattern for Flask app.
    This pattern allows for better testing and multiple instances.
    """
    app = Flask(__name__,
                template_folder='web/templates',
                static_folder='web/static')

    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app.config.from_object(f'app.config.{config_name.capitalize()}Config')

    # Security: Ensure secret key is set
    if not app.config.get('SECRET_KEY'):
        if config_name == 'production':
            raise ValueError("SECRET_KEY must be set in production!")
        app.config['SECRET_KEY'] = os.urandom(32).hex()

    # SECURITY FIX: Enforce DEBUG=False in production
    if config_name == 'production':
        app.config['DEBUG'] = False
        app.config['TESTING'] = False

    # Initialize extensions with app
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)

    # SECURITY FIX: Restrict CORS origins - no wildcard in production
    if config_name == 'production':
        allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',')
        allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
        socketio.init_app(app, cors_allowed_origins=allowed_origins or None)
    else:
        # Development: Allow localhost only
        socketio.init_app(app, cors_allowed_origins=[
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "http://localhost:3000"
        ])

    # Security headers configuration
    # In development, be more permissive for easier testing
    if config_name == 'production':
        Talisman(app,
                 force_https=True,
                 strict_transport_security=True,
                 strict_transport_security_max_age=31536000,
                 session_cookie_secure=True,
                 session_cookie_http_only=True,
                 session_cookie_samesite='Lax',
                 content_security_policy={
                     'default-src': "'self'",
                     'script-src': ["'self'", "'unsafe-inline'"],
                     'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                     'font-src': ["'self'", "https://fonts.gstatic.com"],
                     'img-src': ["'self'", "data:"],
                     'connect-src': ["'self'"],
                     'frame-ancestors': "'none'",
                     'form-action': "'self'",
                 },
                 x_content_type_options=True,
                 x_xss_protection=True,
                 referrer_policy='strict-origin-when-cross-origin'
                 )
    else:
        # Development: Disable CSP to avoid breaking Tailwind CSS
        Talisman(app,
                 force_https=False,
                 strict_transport_security=False,
                 session_cookie_secure=False,
                 content_security_policy=None,  # Disable CSP in development
                 x_content_type_options=True,
                 x_xss_protection=True
                 )

    # Configure login manager
    login_manager.login_view = 'web.login'
    login_manager.login_message_category = 'info'

    # Register blueprints
    from app.web.routes import web_bp
    from app.api.routes import api_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    # SECURITY: Exempt API blueprint from CSRF (API uses JSON and rate limiting instead)
    # API endpoints are protected by rate limiting and access controls
    csrf.exempt(api_bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    # Register error handlers
    register_error_handlers(app)

    return app


def register_error_handlers(app):
    """Register custom error handlers for better security."""

    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad Request', 'message': 'Invalid request parameters'}, 400

    @app.errorhandler(401)
    def unauthorized(error):
        return {'error': 'Unauthorized', 'message': 'Authentication required'}, 401

    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Forbidden', 'message': 'Access denied'}, 403

    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not Found', 'message': 'Resource not found'}, 404

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return {'error': 'Rate Limit Exceeded', 'message': 'Too many requests'}, 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}, 500
