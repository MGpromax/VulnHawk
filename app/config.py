"""
VulnHawk Configuration Module

Secure configuration management following Flask best practices.
All sensitive values are loaded from environment variables.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class BaseConfig:
    """Base configuration with secure defaults."""

    # Application
    APP_NAME = 'VulnHawk'
    APP_VERSION = '1.0.0'

    # Security - NEVER hardcode in production
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', os.urandom(32).hex())

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///vulnhawk.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }

    # Session Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = "100 per hour"

    # Scanner Configuration
    SCANNER_MAX_DEPTH = 10
    SCANNER_MAX_PAGES = 1000
    SCANNER_TIMEOUT = 30
    SCANNER_CONCURRENT_REQUESTS = 10
    SCANNER_DELAY_BETWEEN_REQUESTS = 0.5  # seconds
    SCANNER_USER_AGENT = 'VulnHawk Security Scanner/1.0 (+https://github.com/manojgowda/vulnhawk)'

    # Report Configuration
    REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports_output')
    MAX_REPORT_AGE_DAYS = 30

    # File Upload (for authenticated scans)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'json', 'csv'}

    # Celery (Background Tasks)
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')


class DevelopmentConfig(BaseConfig):
    """Development configuration with relaxed security for testing."""

    DEBUG = True
    TESTING = False

    # Relaxed security for development
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True  # Keep CSRF even in dev

    # SQLite for development
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vulnhawk_dev.db'

    # More verbose logging
    LOG_LEVEL = 'DEBUG'


class TestingConfig(BaseConfig):
    """Testing configuration."""

    DEBUG = True
    TESTING = True

    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

    # Disable CSRF for easier testing
    WTF_CSRF_ENABLED = False

    # Faster scans for testing
    SCANNER_MAX_DEPTH = 2
    SCANNER_MAX_PAGES = 10
    SCANNER_TIMEOUT = 5


class ProductionConfig(BaseConfig):
    """Production configuration with maximum security."""

    DEBUG = False
    TESTING = False

    # Security: These MUST be set via environment variables in production
    # For development/testing, we use a generated key
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', os.urandom(32).hex())

    # Production database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///vulnhawk_prod.db')

    # Strict security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'

    # Production logging
    LOG_LEVEL = 'WARNING'

    # Stricter rate limiting
    RATELIMIT_DEFAULT = "50 per hour"


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
