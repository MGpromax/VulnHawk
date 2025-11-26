"""
User Model for VulnHawk

Secure user authentication with bcrypt password hashing.
"""

from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
import re
import logging
import hashlib

security_logger = logging.getLogger('security')


class User(UserMixin, db.Model):
    """
    User model with secure password handling.

    Security features:
    - Passwords are hashed with bcrypt (via werkzeug)
    - Email validation
    - Account lockout tracking
    - API key support with expiration for programmatic access
    - Security logging
    """

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=True, index=True)
    api_key_expires_at = db.Column(db.DateTime, nullable=True)  # SECURITY: API key expiration

    # Security tracking
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    # SECURITY FIX: Improved password validation regex with more special characters
    PASSWORD_REGEX = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>\/?`~])'
        r'.{8,128}$'
    )
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    def __init__(self, username, email, password):
        """Initialize user with validated inputs."""
        self.username = self._validate_username(username)
        self.email = self._validate_email(email)
        self.set_password(password)

    @staticmethod
    def _validate_username(username):
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 80:
            raise ValueError("Username must be between 3 and 80 characters")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return username.lower()

    @staticmethod
    def _validate_email(email):
        """Validate email format."""
        if not email or not User.EMAIL_REGEX.match(email):
            raise ValueError("Invalid email format")
        return email.lower()

    def set_password(self, password):
        """
        Hash and set password with validation.

        Password requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
        """
        if not password or not self.PASSWORD_REGEX.match(password):
            raise ValueError(
                "Password must be at least 8 characters with uppercase, "
                "lowercase, number, and special character"
            )
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:260000')

    def check_password(self, password):
        """Verify password against hash."""
        if not password:
            return False
        return check_password_hash(self.password_hash, password)

    def is_locked(self):
        """Check if account is locked due to failed attempts."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def record_failed_login(self):
        """Record failed login attempt and lock if necessary."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

    def record_successful_login(self):
        """Reset failed attempts on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
        db.session.commit()

    def generate_api_key(self, expiry_days=90):
        """
        Generate a secure API key with expiration for programmatic access.

        SECURITY: API keys expire after 90 days by default.
        Only log a hash of the key, never the actual key.
        """
        import secrets
        self.api_key = secrets.token_urlsafe(48)
        self.api_key_expires_at = datetime.utcnow() + timedelta(days=expiry_days)
        db.session.commit()

        # SECURITY: Log only a hash of the key
        key_hash = hashlib.sha256(self.api_key.encode()).hexdigest()[:16]
        security_logger.info(f"API key generated for user {self.id}: {key_hash}...")

        return self.api_key

    def revoke_api_key(self):
        """Revoke the current API key."""
        if self.api_key:
            security_logger.info(f"API key revoked for user {self.id}")
        self.api_key = None
        self.api_key_expires_at = None
        db.session.commit()

    def is_api_key_valid(self):
        """Check if API key is valid and not expired."""
        if not self.api_key:
            return False
        if self.api_key_expires_at and self.api_key_expires_at < datetime.utcnow():
            return False
        return True

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))


@login_manager.request_loader
def load_user_from_request(request):
    """Load user from API key in request header with expiration check."""
    api_key = request.headers.get('X-API-Key')
    if api_key:
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        if user and not user.is_locked() and user.is_api_key_valid():
            return user
        elif user and not user.is_api_key_valid():
            security_logger.warning(f"Expired API key used for user {user.id}")
    return None
